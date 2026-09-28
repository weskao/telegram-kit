"""Secure Telegram notifications for any Python project. Stdlib only.

``pip``/``uv`` install this repository and ``import telegram_kit`` — it has no
dependency on the ``codex_reset_watch`` CLI, so importing it is cheap.

    import telegram_kit

    telegram_kit.notify("build finished", service="my-app", chat_id="123456789")

    store = telegram_kit.CredentialStore("my-app")
    token = telegram_kit.read_hidden("Telegram bot token (hidden): ")
    if token and store.set("telegram_bot_token", token):
        print("stored as", telegram_kit.mask_secret(token))

What it guarantees, whichever project uses it:

* The bot token lives only in the OS credential store, namespaced by
  *service*: macOS Keychain (``security``), Linux Secret Service
  (``secret-tool``) or Windows DPAPI (PowerShell). With none available,
  nothing is stored; there is no plaintext or obfuscated fallback.
* The secret never enters an argument vector (``ps``, shell history): every
  helper receives it on stdin.
* Reads never raise. A locked keyring or missing helper just means "no secret".
* ``TG_BOT_TOKEN`` / ``TG_CHAT_ID`` are fallbacks for values the caller did
  not configure, each on its own.

Passing ``service="codex-reset-watch"`` reuses the token that ``crw config``
stored. The chat id is ordinary configuration, so each project keeps its own.
"""
from __future__ import annotations

import contextlib
import functools
import getpass
import http.client
import json
import os
import pathlib
import platform
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import uuid
import warnings
from collections.abc import Callable, Mapping

IS_MACOS = platform.system() == "Darwin"
IS_WINDOWS = platform.system() == "Windows"

#: How long a credential helper may take before we give up on it.
TIMEOUT_SECONDS = 10

#: Environment variables that stand in for credentials the caller did not set.
TOKEN_ENV, CHAT_ID_ENV = "TG_BOT_TOKEN", "TG_CHAT_ID"
TOKEN_KEY = "telegram_bot_token"

BACKEND_LABELS = {
    "keychain": "macOS Keychain",
    "libsecret": "Secret Service (libsecret)",
    "dpapi": "Windows DPAPI",
}

_API = "https://api.telegram.org/bot{token}/sendMessage"
_PHOTO_API = "https://api.telegram.org/bot{token}/sendPhoto"


# ── owner-only files ─────────────────────────────────────────────────────────

def write_private(target: pathlib.Path, content: str) -> None:
    """Atomically write owner-only text; fail before writing if protection fails."""
    target = pathlib.Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        raise OSError("Refusing to overwrite a symlink")
    temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
    created = False
    try:
        if os.name == "nt":
            # The ACL is attached at creation, before content is written.
            # The path and content travel on stdin, never the command line.
            script = (
                "$ErrorActionPreference='Stop'; "
                "$data=[Console]::In.ReadToEnd() | ConvertFrom-Json; "
                "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User; "
                "$acl=[Security.AccessControl.FileSecurity]::new(); "
                "$acl.SetAccessRuleProtection($true,$false); $acl.SetOwner($sid); "
                "$rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,"
                "[Security.AccessControl.FileSystemRights]::FullControl,"
                "[Security.AccessControl.AccessControlType]::Allow); "
                "$acl.AddAccessRule($rule); "
                "$file=[IO.FileStream]::new($data.path,[IO.FileMode]::CreateNew,"
                "[Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::None,4096,"
                "[IO.FileOptions]::None,$acl); "
                "$writer=[IO.StreamWriter]::new($file,[Text.UTF8Encoding]::new($false)); "
                "try { $writer.Write($data.content) } finally { $writer.Dispose() }"
            )
            created = True  # PowerShell may create it before failing or timing out
            try:
                result = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                    input=json.dumps({"path": str(temporary), "content": content}, ensure_ascii=True),
                    capture_output=True, text=True, timeout=15, check=False,
                )
            except subprocess.SubprocessError as exc:
                raise OSError("Unable to create an owner-only file") from exc
            if result.returncode:
                raise OSError("Unable to create an owner-only file")
        else:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created = True
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(content)
        os.replace(temporary, target)
        created = False
    finally:
        if created:
            temporary.unlink(missing_ok=True)


# ── credential store ─────────────────────────────────────────────────────────

def _run(argv, stdin: str | None = None) -> tuple[int, str]:
    """The single subprocess funnel: ``(returncode, stdout)``.

    Tests replace this whole function, so nothing above it needs a keychain.
    """
    completed = subprocess.run(
        list(argv), input=stdin, capture_output=True, text=True,
        timeout=TIMEOUT_SECONDS, check=False,
    )
    return completed.returncode, completed.stdout


def _unhex(secret: str) -> str:
    """Undo the hex encoding ``security -w`` applies to "non-clean" secrets.

    It decides that per item, so the shape of the output is the only signal.
    ``security`` prints a secret of printable ASCII as-is, so a decode that is
    all printable ASCII means the output was never encoded. All-digit output
    is kept too: a numeric chat id such as ``1122334455`` is valid hex whose
    decode (``\x11"3DU``) holds a control byte, so the ASCII check alone
    would wrongly decode it. Telegram tokens contain ``:`` so they never
    take this path.
    """
    if not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", secret) or secret.isdigit():
        return secret
    try:
        decoded = bytes.fromhex(secret).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return secret
    return secret if decoded.isascii() and decoded.isprintable() else decoded


def _batch_quote(value: str) -> str:
    """Escape a value for a double-quoted argument in ``security -i`` batch mode.

    Rejects newlines outright: batch mode is line-oriented, so an embedded one
    would end the command and let the rest be read as a second one.
    """
    if "\n" in value or "\r" in value:
        raise ValueError("security batch argument contains a newline")
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _detect_backend() -> str | None:
    if IS_MACOS and shutil.which("security"):
        return "keychain"
    if IS_WINDOWS and shutil.which("powershell.exe"):
        return "dpapi"
    if shutil.which("secret-tool"):
        return "libsecret"
    return None


@functools.lru_cache(maxsize=1)
def backend() -> str | None:
    """Which credential store this machine has, or ``None``. Probed once."""
    return _detect_backend()


def available() -> bool:
    return backend() is not None


def backend_label() -> str:
    """A human name for the active store, for ``doctor`` and the config menu."""
    return BACKEND_LABELS.get(backend() or "", "none")


def legacy_windows_env_token_present() -> bool:
    """Detect a token left by older `setx` installs without reading it aloud."""
    if not IS_WINDOWS:
        return False
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            value, _ = winreg.QueryValueEx(key, "TG_BOT_TOKEN")
            return bool(value)
    except OSError:
        return False


def _default_dpapi_dir(service: str) -> pathlib.Path:
    base = os.environ.get("APPDATA") or str(pathlib.Path.home() / "AppData" / "Roaming")
    return pathlib.Path(base) / service


class CredentialStore:
    """The OS credential store, scoped to one *service* name.

    *dpapi_dir* returns the folder for Windows DPAPI ciphertext files. It is a
    callable so a caller whose config folder can move (an env override) is
    asked each time rather than once.
    """

    def __init__(self, service: str,
                 dpapi_dir: Callable[[], pathlib.Path] | None = None) -> None:
        self.service = service
        self._dpapi_dir = dpapi_dir or (lambda: _default_dpapi_dir(service))

    def _dpapi_path(self, key: str) -> pathlib.Path:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", key):
            raise ValueError("Invalid credential identifier")
        return pathlib.Path(self._dpapi_dir()) / f"{key}.dpapi"

    def get(self, key: str) -> str:
        """The stored secret for *key*, or ``""`` when there is none.

        Never raises: a locked keyring, a missing helper or a denied prompt all
        mean "no secret", which the caller already handles.
        """
        active = backend()
        if active is None:
            return ""
        with contextlib.suppress(Exception):
            if active == "keychain":
                code, out = _run(["security", "find-generic-password",
                                  "-s", self.service, "-a", key, "-w"])
                if code == 0:
                    return _unhex(out.strip())
            elif active == "libsecret":
                code, out = _run(["secret-tool", "lookup", "service", self.service, "account", key])
            else:  # dpapi
                path = self._dpapi_path(key)
                if not path.exists():
                    return ""
                code, out = _run([
                    "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                    ("$s = [Console]::In.ReadToEnd().Trim() | ConvertTo-SecureString; "
                     "[Runtime.InteropServices.Marshal]::PtrToStringAuto("
                     "[Runtime.InteropServices.Marshal]::SecureStringToBSTR($s))"),
                ], stdin=path.read_text(encoding="utf-8"))
            if code == 0:
                return out.strip()
        return ""

    def set(self, key: str, value: str) -> bool:
        """Store *value* for *key*. ``False`` when it could not be stored securely.

        An empty *value* deletes the item instead of storing a blank — that is how
        the menu clears a token.
        """
        if not value:
            return self.delete(key)
        active = backend()
        if active is None:
            return False  # refuse rather than write plaintext; see the module docstring
        with contextlib.suppress(Exception):
            if active == "keychain":
                # `add-generic-password -w` with no argument does NOT read stdin — it
                # opens /dev/tty and prompts, so piping the secret there stored an
                # empty item and still exited 0. Batch mode (`security -i`) takes the
                # whole command on stdin, which keeps the secret out of every argv
                # (i.e. out of `ps`), and -X hex-encodes it past the tokenizer's
                # quoting and newline rules. -U updates in place rather than stacking
                # duplicate items.
                command = 'add-generic-password -U -s "{}" -a "{}" -X {}\n'.format(
                    _batch_quote(self.service), _batch_quote(key), value.encode("utf-8").hex())
                code, _ = _run(["security", "-i"], stdin=command)
            elif active == "libsecret":
                code, _ = _run(["secret-tool", "store", "--label", f"{self.service} {key}",
                                "service", self.service, "account", key], stdin=value)
            else:  # dpapi
                path = self._dpapi_path(key)
                code, encrypted = _run([
                    "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                    ("$in = [Console]::In.ReadToEnd().Trim(); "
                     "ConvertTo-SecureString $in -AsPlainText -Force | ConvertFrom-SecureString"),
                ], stdin=value)
                if code != 0 or not encrypted.strip():
                    return False
                write_private(path, encrypted.strip())
            return code == 0
        return False

    def delete(self, key: str) -> bool:
        """Remove the stored secret for *key*. ``False`` when there was nothing to remove."""
        active = backend()
        if active is None:
            return False
        with contextlib.suppress(Exception):
            if active == "keychain":
                code, _ = _run(["security", "delete-generic-password", "-s", self.service, "-a", key])
            elif active == "libsecret":
                code, _ = _run(["secret-tool", "clear", "service", self.service, "account", key])
            else:  # dpapi
                path = self._dpapi_path(key)
                path.unlink(missing_ok=True)
                return True
            return code == 0
        return False


# ── resolving, sending, entering, showing ────────────────────────────────────

def resolve_credentials(token: str = "", chat_id: str = "", *,
                        environ: Mapping[str, str] | None = None) -> tuple[str, str]:
    """``(token, chat_id)``: what the caller configured, else the environment.

    Each value falls back on its own, and blank counts as unset. Configured
    values win so a stale ``TG_BOT_TOKEN`` in a shell profile cannot keep
    notifying through a bot the user already replaced.
    """
    env = os.environ if environ is None else environ
    return (str(token or "").strip() or env.get(TOKEN_ENV, "").strip(),
            str(chat_id or "").strip() or env.get(CHAT_ID_ENV, "").strip())


#: Same label as ``TG_TMUX_LABEL`` in ~/.claude/scripts/tg-tag.sh.
TMUX_LABEL = "🪟 Tmux"


def tmux_line() -> str:
    """``"🪟 Tmux: <session>"`` when running inside tmux, else ``""``. Never raises.

    Same rule as ``tg_tag_lines`` in ~/.claude/scripts/tg-tag.sh, so the phone shows
    which tmux session to attach to.
    """
    if not os.environ.get("TMUX"):
        return ""
    pane = os.environ.get("TMUX_PANE")
    try:
        code, out = _run(["tmux", "display-message", "-p", *(["-t", pane] if pane else []), "#S"])
    except (OSError, subprocess.SubprocessError):
        return ""
    name = out.strip() if code == 0 else ""
    return f"{TMUX_LABEL}: {name}" if name else ""


def _tagged(text: str) -> str:
    """*text* with the tmux line on its own line, unless it already carries it."""
    line = tmux_line()
    return f"{text}\n{line}" if line and line not in text else text


def send_message(token: str, chat_id: str, text: str, *, timeout: float = 10) -> bool:
    """POST one sendMessage to the Bot API. False on missing credentials or any failure.

    Inside tmux the text ends with a ``tmux_line()``.
    """
    if not token or not chat_id:
        return False
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": _tagged(text)}).encode("utf-8")
    return _post(urllib.request.Request(_API.format(token=token), data=data, method="POST"), timeout)


def _post(request: urllib.request.Request, timeout: float) -> bool:
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response.read()
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):
        return False  # incl. InvalidURL from a hand-corrupted token
    return True


#: Telegram's caption limit, in UTF-16 code units (how the Bot API counts).
CAPTION_LIMIT = 1024


def send_photo(token: str, chat_id: str, photo: str | os.PathLike, caption: str = "", *,
               timeout: float = 30) -> bool:
    """POST one sendPhoto: the image at *photo* with *caption* as its text, in one message.

    A caption over ``CAPTION_LIMIT`` would be rejected outright, so the image goes
    uncaptioned and the full text follows as a ``send_message`` — delivered, not dropped.
    False on missing credentials, an unreadable image or any failure; never raises.
    """
    if not token or not chat_id:
        return False
    path = pathlib.Path(photo)
    try:
        image = path.read_bytes()
    except OSError:
        return False
    caption = _tagged(caption) if caption else ""  # measured with its tmux line
    fits = len(caption.encode("utf-16-le")) // 2 <= CAPTION_LIMIT
    boundary = uuid.uuid4().hex
    filename = re.sub(r'["\r\n\\]', "_", path.name)
    fields = [("chat_id", chat_id), ("caption", caption if fits else "")]
    parts = [(f'name="{name}"', b"", value.encode("utf-8")) for name, value in fields if value]
    parts.append((f'name="photo"; filename="{filename}"',
                  b"Content-Type: application/octet-stream\r\n", image))
    body = b"".join(f"--{boundary}\r\nContent-Disposition: form-data; {disposition}\r\n".encode()
                    + ctype + b"\r\n" + value + b"\r\n" for disposition, ctype, value in parts)
    body += f"--{boundary}--\r\n".encode()
    request = urllib.request.Request(
        _PHOTO_API.format(token=token), data=body, method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    return _post(request, timeout) and (fits or send_message(token, chat_id, caption))


def notify(text: str, *, service: str, chat_id: str = "", token_key: str = TOKEN_KEY,
           store: CredentialStore | None = None) -> bool:
    """Send *text* with *service*'s stored token. Never raises; False on failure."""
    store = store or CredentialStore(service)
    token, chat = resolve_credentials(store.get(token_key), chat_id)
    return send_message(token, chat, text)


def read_hidden(prompt: str, *, ask: Callable[[str], str] | None = None) -> str | None:
    """Read a secret without echo. ``None`` when echo cannot be disabled or input ends.

    ``getpass`` silently falls back to an echoing prompt when it has no
    terminal; that warning is treated as a refusal, never as consent.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return (ask or getpass.getpass)(prompt).strip()
    except (EOFError, OSError, getpass.GetPassWarning):
        return None


def mask_secret(secret: str) -> str:
    """Stars, plus at most the last 4 characters — never enough to reuse."""
    if not secret:
        return ""
    return "*" * 8 + secret[-4:] if len(secret) > 12 else "*" * 8
