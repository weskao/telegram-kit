"""The reusable Telegram kit other projects import. Synthetic credentials only."""
import getpass
import os
import pathlib
import subprocess
import sys
import tempfile
import types
import unittest
import urllib.parse
import warnings
from unittest import mock

import telegram_kit

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Sends append a "🪟 Tmux: <session>" line when run inside tmux; the exact-text
# assertions below must not depend on where the suite runs. TmuxTagTests opts in.
_no_tmux = mock.patch.dict(os.environ)


def setUpModule():
    _no_tmux.start()
    os.environ.pop("TMUX", None)
    os.environ.pop("TMUX_PANE", None)


def tearDownModule():
    _no_tmux.stop()


class WindowsOs:
    """Makes ``telegram_kit.os.name`` read ``"nt"`` without touching the real
    global ``os`` module — patching that directly breaks pathlib for every
    other test in the process (it stops knowing which flavour it's on)."""
    name = "nt"

    def __getattr__(self, attr):
        return getattr(os, attr)


class Recorder:
    def __init__(self, *results):
        self.calls, self.results = [], list(results)

    def __call__(self, argv, stdin=None):
        self.calls.append((list(argv), stdin))
        return self.results.pop(0) if self.results else (0, "")


def pinned(name, run):
    return mock.patch.multiple(telegram_kit, backend=lambda: name, _run=run)


class StandaloneTests(unittest.TestCase):
    def test_importing_the_kit_needs_only_the_standard_library(self):
        """No project this kit is vendored/depended into should have to
        install anything else just to get ``import telegram_kit``."""
        result = subprocess.run(  # noqa: PLW1510 - want a status, not to raise
            [sys.executable, "-I", "-c", "import telegram_kit"],
            cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
        )
        self.assertEqual(result.returncode, 0)


class CredentialStoreTests(unittest.TestCase):
    def test_each_service_gets_its_own_keychain_namespace(self):
        run = Recorder((0, "fake-token\n"), (0, ""))
        store = telegram_kit.CredentialStore("other-app")
        with pinned("keychain", run):
            self.assertEqual(store.get("telegram_bot_token"), "fake-token")
            self.assertTrue(store.set("telegram_bot_token", "fake-token"))
        self.assertIn("other-app", run.calls[0][0])
        self.assertIn('"other-app"', run.calls[1][1])
        self.assertNotIn("fake-token", " ".join(run.calls[1][0]) + run.calls[1][1])

    def test_without_a_backend_nothing_is_stored(self):
        store = telegram_kit.CredentialStore("other-app")
        with pinned(None, Recorder()):
            self.assertFalse(store.set("telegram_bot_token", "fake-token"))
            self.assertEqual(store.get("telegram_bot_token"), "")

    def test_dpapi_files_live_in_the_callers_directory(self):
        with tempfile.TemporaryDirectory() as d:
            store = telegram_kit.CredentialStore("other-app", dpapi_dir=lambda: pathlib.Path(d))
            with pinned("dpapi", Recorder((0, "ciphertext\n"))):
                self.assertTrue(store.set("telegram_bot_token", "fake-token"))
            self.assertEqual((pathlib.Path(d) / "telegram_bot_token.dpapi").read_text(), "ciphertext")

    def test_dpapi_key_cannot_escape_its_directory(self):
        with tempfile.TemporaryDirectory() as d:
            store = telegram_kit.CredentialStore("other-app", dpapi_dir=lambda: pathlib.Path(d))
            with pinned("dpapi", Recorder((0, "ciphertext\n"))):
                self.assertFalse(store.set("../escape", "fake-token"))

    def test_dpapi_get_returns_empty_when_the_file_is_missing(self):
        with tempfile.TemporaryDirectory() as d:
            store = telegram_kit.CredentialStore("other-app", dpapi_dir=lambda: pathlib.Path(d))
            with pinned("dpapi", Recorder()):
                self.assertEqual(store.get("telegram_bot_token"), "")

    def test_dpapi_get_decrypts_the_stored_file(self):
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "telegram_bot_token.dpapi").write_text("ciphertext")
            store = telegram_kit.CredentialStore("other-app", dpapi_dir=lambda: pathlib.Path(d))
            with pinned("dpapi", Recorder((0, "fake-token\n"))):
                self.assertEqual(store.get("telegram_bot_token"), "fake-token")

    def test_dpapi_set_fails_when_powershell_reports_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            store = telegram_kit.CredentialStore("other-app", dpapi_dir=lambda: pathlib.Path(d))
            with pinned("dpapi", Recorder((1, ""))):
                self.assertFalse(store.set("telegram_bot_token", "fake-token"))
            self.assertFalse((pathlib.Path(d) / "telegram_bot_token.dpapi").exists())

    def test_dpapi_delete_removes_the_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "telegram_bot_token.dpapi"
            path.write_text("ciphertext")
            store = telegram_kit.CredentialStore("other-app", dpapi_dir=lambda: pathlib.Path(d))
            with pinned("dpapi", Recorder()):
                self.assertTrue(store.delete("telegram_bot_token"))
            self.assertFalse(path.exists())

    def test_dpapi_delete_succeeds_even_when_nothing_was_stored(self):
        with tempfile.TemporaryDirectory() as d:
            store = telegram_kit.CredentialStore("other-app", dpapi_dir=lambda: pathlib.Path(d))
            with pinned("dpapi", Recorder()):
                self.assertTrue(store.delete("telegram_bot_token"))

    def test_delete_without_a_backend_reports_failure(self):
        store = telegram_kit.CredentialStore("other-app")
        with pinned(None, Recorder()):
            self.assertFalse(store.delete("telegram_bot_token"))


class CredentialResolutionTests(unittest.TestCase):
    def test_configured_values_win_over_environment(self):
        env = {"TG_BOT_TOKEN": "env-token", "TG_CHAT_ID": "222"}
        self.assertEqual(telegram_kit.resolve_credentials("fake-token", "111", environ=env),
                         ("fake-token", "111"))

    def test_each_value_falls_back_to_environment_on_its_own(self):
        env = {"TG_BOT_TOKEN": " env-token ", "TG_CHAT_ID": "222"}
        self.assertEqual(telegram_kit.resolve_credentials("", "111", environ=env), ("env-token", "111"))
        self.assertEqual(telegram_kit.resolve_credentials("fake-token", " ", environ=env),
                         ("fake-token", "222"))


class SendMessageTests(unittest.TestCase):
    def test_text_only_is_one_form_encoded_send_message_post(self):
        """No image, no photo code path: the text goes out exactly as a plain sendMessage."""
        sent = []

        def urlopen(request, timeout):
            sent.append((request, timeout))
            return _Response()

        with mock.patch("urllib.request.urlopen", side_effect=urlopen):
            self.assertTrue(telegram_kit.send_message("fake-token", "111", "中文 & x=1"))
        (request, timeout), = sent
        self.assertEqual(request.full_url, "https://api.telegram.org/botfake-token/sendMessage")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(urllib.parse.parse_qs(request.data.decode()), {"chat_id": ["111"], "text": ["中文 & x=1"]})
        self.assertEqual(timeout, 10)

    def test_false_on_missing_credentials_without_a_network_call(self):
        with mock.patch("urllib.request.urlopen") as urlopen:
            self.assertFalse(telegram_kit.send_message("", "111", "hello"))
            self.assertFalse(telegram_kit.send_message("fake-token", "", "hello"))
        urlopen.assert_not_called()

    def test_false_on_a_network_error_never_raises(self):
        import urllib.error
        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("offline")):
            self.assertFalse(telegram_kit.send_message("fake-token", "111", "hello"))

    def test_false_on_a_malformed_token_never_raises(self):
        """A hand-corrupted token can make the URL itself invalid (``InvalidURL``,
        a ``ValueError`` subclass) — still reported as a failed send, not a crash."""
        with mock.patch("urllib.request.urlopen", side_effect=ValueError("bad url")):
            self.assertFalse(telegram_kit.send_message("not a token", "111", "hello"))


class _Response:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return b"{}"


def _form_fields(request) -> dict:
    """Parse the multipart body *request* carries: ``{name: (filename, bytes)}``."""
    import email.parser
    import email.policy
    raw = b"Content-Type: " + request.get_header("Content-type").encode() + b"\r\n\r\n" + request.data
    msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(raw)
    return {part.get_param("name", header="content-disposition"):
            (part.get_filename(), part.get_payload(decode=True)) for part in msg.iter_parts()}


class SendPhotoTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.photo = pathlib.Path(tmp.name) / "shot.png"
        self.photo.write_bytes(b"\x89PNG fake image bytes")
        self.sent = []

    def urlopen(self, request, timeout):
        self.sent.append(request)
        return _Response()

    def test_sends_image_and_caption_in_one_send_photo_call(self):
        with mock.patch("urllib.request.urlopen", side_effect=self.urlopen):
            self.assertTrue(telegram_kit.send_photo("fake-token", "111", self.photo, "build 42 ✅"))
        self.assertEqual(len(self.sent), 1)
        self.assertIn("/botfake-token/sendPhoto", self.sent[0].full_url)
        fields = _form_fields(self.sent[0])
        self.assertEqual(fields["chat_id"], (None, b"111"))
        self.assertEqual(fields["caption"], (None, "build 42 ✅".encode()))
        self.assertEqual(fields["photo"], ("shot.png", b"\x89PNG fake image bytes"))

    def test_without_a_caption_sends_only_the_image(self):
        with mock.patch("urllib.request.urlopen", side_effect=self.urlopen):
            self.assertTrue(telegram_kit.send_photo("fake-token", "111", str(self.photo)))
        self.assertNotIn("caption", _form_fields(self.sent[0]))

    def test_caption_over_the_limit_follows_the_image_as_a_message(self):
        """Telegram rejects a caption over 1024 characters; the text must still arrive."""
        long_text = "x" * 1025
        with mock.patch("urllib.request.urlopen", side_effect=self.urlopen):
            self.assertTrue(telegram_kit.send_photo("fake-token", "111", self.photo, long_text))
        self.assertEqual([r.full_url.rsplit("/", 1)[1] for r in self.sent], ["sendPhoto", "sendMessage"])
        self.assertNotIn("caption", _form_fields(self.sent[0]))
        self.assertEqual(urllib.parse.parse_qs(self.sent[1].data.decode())["text"], [long_text])

    def test_caption_at_the_limit_stays_on_the_image(self):
        """The limit counts UTF-16 units: 512 emoji = 1024 units still fit."""
        with mock.patch("urllib.request.urlopen", side_effect=self.urlopen):
            self.assertTrue(telegram_kit.send_photo("fake-token", "111", self.photo, "🙂" * 512))
        self.assertEqual(len(self.sent), 1)
        self.assertIn("caption", _form_fields(self.sent[0]))

    def test_false_on_missing_credentials_without_a_network_call(self):
        with mock.patch("urllib.request.urlopen") as urlopen:
            self.assertFalse(telegram_kit.send_photo("", "111", self.photo))
            self.assertFalse(telegram_kit.send_photo("fake-token", "", self.photo))
        urlopen.assert_not_called()

    def test_false_on_a_missing_image_never_raises(self):
        with mock.patch("urllib.request.urlopen") as urlopen:
            self.assertFalse(telegram_kit.send_photo("fake-token", "111", self.photo.with_name("gone.png")))
        urlopen.assert_not_called()

    def test_false_on_a_network_error_never_raises(self):
        import urllib.error
        with mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("offline")):
            self.assertFalse(telegram_kit.send_photo("fake-token", "111", self.photo, "hi"))


class TmuxTagTests(unittest.TestCase):
    """Same rule as ~/.claude/scripts/tg-tag.sh: inside tmux every text message and
    non-empty caption ends with "🪟 Tmux: <session>" on its own line; else untouched."""

    def setUp(self):
        self.sent = []
        patcher = mock.patch("urllib.request.urlopen", side_effect=self.urlopen)
        patcher.start()
        self.addCleanup(patcher.stop)

    def urlopen(self, request, timeout):
        self.sent.append(request)
        return _Response()

    def text(self, i=0):
        return urllib.parse.parse_qs(self.sent[i].data.decode())["text"][0]

    def test_inside_tmux_the_session_line_follows_the_text(self):
        run = Recorder((0, "demo_session\n"))
        with mock.patch.dict(os.environ, {"TMUX": "/tmp/x,1,0", "TMUX_PANE": "%1"}), \
                mock.patch.object(telegram_kit, "_run", run):
            self.assertTrue(telegram_kit.send_message("fake-token", "111", "hello"))
        self.assertEqual(self.text(), "hello\n🪟 Tmux: demo_session")
        self.assertEqual(run.calls[0][0], ["tmux", "display-message", "-p", "-t", "%1", "#S"])

    def test_outside_tmux_the_text_is_untouched_and_tmux_never_runs(self):
        run = Recorder()
        with mock.patch.object(telegram_kit, "_run", run):
            telegram_kit.send_message("fake-token", "111", "hello")
        self.assertEqual((self.text(), run.calls), ("hello", []))

    def test_no_session_name_means_no_line(self):
        """tmux failing, printing nothing, or missing entirely: send the text as-is."""
        def missing(argv, stdin=None):
            raise FileNotFoundError("tmux")
        for run in (Recorder((1, "")), Recorder((0, "\n")), missing):
            with self.subTest(run=run), mock.patch.dict(os.environ, {"TMUX": "/tmp/x,1,0"}), \
                    mock.patch.object(telegram_kit, "_run", run):
                self.sent.clear()
                self.assertTrue(telegram_kit.send_message("fake-token", "111", "hello"))
                self.assertEqual(self.text(), "hello")

    def test_a_line_the_text_already_carries_is_not_repeated(self):
        with mock.patch.dict(os.environ, {"TMUX": "/tmp/x,1,0"}), \
                mock.patch.object(telegram_kit, "_run", Recorder((0, "demo_session\n"))):
            telegram_kit.send_message("fake-token", "111", "card\n🪟 Tmux: demo_session")
        self.assertEqual(self.text(), "card\n🪟 Tmux: demo_session")

    def test_caption_is_tagged_once_even_when_it_follows_as_a_message(self):
        with tempfile.TemporaryDirectory() as d:
            photo = pathlib.Path(d) / "shot.png"
            photo.write_bytes(b"png")
            with mock.patch.dict(os.environ, {"TMUX": "/tmp/x,1,0"}), \
                    mock.patch.object(telegram_kit, "_run", lambda argv, stdin=None: (0, "demo_session\n")):
                telegram_kit.send_photo("fake-token", "111", photo, "cap")
                telegram_kit.send_photo("fake-token", "111", photo)
                telegram_kit.send_photo("fake-token", "111", photo, "x" * 1025)
        self.assertEqual(_form_fields(self.sent[0])["caption"], (None, "cap\n🪟 Tmux: demo_session".encode()))
        self.assertNotIn("caption", _form_fields(self.sent[1]))  # no caption, nothing to tag
        self.assertEqual(self.text(3), "x" * 1025 + "\n🪟 Tmux: demo_session")


class NotifyTests(unittest.TestCase):
    def test_notify_sends_with_the_services_stored_token(self):
        sent = []

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b"{}"

        def urlopen(request, timeout):
            sent.append(request)
            return Response()

        with pinned("keychain", Recorder((0, "fake-token\n"))), \
                mock.patch("urllib.request.urlopen", side_effect=urlopen), \
                mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(telegram_kit.notify("hello", service="other-app", chat_id="111"))
        self.assertIn("/botfake-token/sendMessage", sent[0].full_url)
        self.assertEqual(urllib.parse.parse_qs(sent[0].data.decode())["chat_id"], ["111"])

    def test_notify_without_credentials_reports_failure(self):
        with pinned(None, Recorder()), mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch("urllib.request.urlopen") as urlopen:
            self.assertFalse(telegram_kit.notify("hello", service="other-app", chat_id="111"))
        urlopen.assert_not_called()


class InputAndDisplayTests(unittest.TestCase):
    def test_hidden_input_refuses_when_echo_cannot_be_disabled(self):
        def echoing(prompt):
            warnings.warn("echo on", getpass.GetPassWarning)
            return "fake-token"
        with warnings.catch_warnings(record=True):
            self.assertIsNone(telegram_kit.read_hidden("Token: ", ask=echoing))

    def test_hidden_input_returns_the_entered_secret(self):
        self.assertEqual(telegram_kit.read_hidden("Token: ", ask=lambda _: " fake-token "), "fake-token")

    def test_mask_never_shows_more_than_four_characters(self):
        self.assertEqual(telegram_kit.mask_secret("123456:ABCDEFGHIJ"), "********GHIJ")
        self.assertEqual(telegram_kit.mask_secret("short"), "********")
        self.assertEqual(telegram_kit.mask_secret(""), "")


class WritePrivateTests(unittest.TestCase):
    def test_writes_owner_only_and_atomically(self):
        with tempfile.TemporaryDirectory() as d:
            target = pathlib.Path(d) / "secret.txt"
            telegram_kit.write_private(target, "content")
            self.assertEqual(target.read_text(), "content")
            if os.name != "nt":
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(pathlib.Path(d).iterdir()), [target])  # no leftover temp file

    def test_refuses_to_overwrite_a_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            real = pathlib.Path(d) / "real.txt"
            real.write_text("untouched")
            link = pathlib.Path(d) / "link.txt"
            link.symlink_to(real)
            with self.assertRaises(OSError):
                telegram_kit.write_private(link, "attacker-controlled")
            self.assertEqual(real.read_text(), "untouched")

    def test_windows_path_runs_powershell_and_cleans_up_on_failure(self):
        def failing_powershell(argv, input, **kwargs):
            pathlib.Path(__import__("json").loads(input)["path"]).write_text("partial")
            return subprocess.CompletedProcess(argv, 1)
        with tempfile.TemporaryDirectory() as d:
            target = pathlib.Path(d) / "secret.txt"
            with mock.patch.object(telegram_kit, "os", WindowsOs()), \
                    mock.patch.object(telegram_kit.subprocess, "run", side_effect=failing_powershell), \
                    self.assertRaises(OSError):
                telegram_kit.write_private(target, "content")
            self.assertEqual(list(pathlib.Path(d).iterdir()), [])

    def test_windows_timeout_is_oserror_and_leaves_no_temp_file(self):
        def slow_powershell(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, 15)
        with tempfile.TemporaryDirectory() as d:
            target = pathlib.Path(d) / "secret.txt"
            with mock.patch.object(telegram_kit, "os", WindowsOs()), \
                    mock.patch.object(telegram_kit.subprocess, "run", side_effect=slow_powershell), \
                    self.assertRaises(OSError):
                telegram_kit.write_private(target, "content")
            self.assertEqual(list(pathlib.Path(d).iterdir()), [])


class SubprocessHelperTests(unittest.TestCase):
    def test_run_executes_and_captures_stdout(self):
        code, out = telegram_kit._run([sys.executable, "-c", "print('hi')"])
        self.assertEqual((code, out.strip()), (0, "hi"))

    def test_unhex_decodes_a_hex_encoded_secret(self):
        self.assertEqual(telegram_kit._unhex("héllo".encode().hex()), "héllo")

    def test_unhex_leaves_a_numeric_chat_id_alone(self):
        self.assertEqual(telegram_kit._unhex("1122334455"), "1122334455")

    def test_unhex_leaves_hex_that_security_would_have_printed_plain_alone(self):
        self.assertEqual(telegram_kit._unhex("41424a"), "41424a")  # decodes to "ABJ"

    def test_unhex_leaves_a_non_hex_secret_alone(self):
        self.assertEqual(telegram_kit._unhex("123456:ABCDEF"), "123456:ABCDEF")

    def test_unhex_leaves_hex_that_is_not_valid_utf8_alone(self):
        garbage = bytes([0xFF, 0xFE]).hex()
        self.assertEqual(telegram_kit._unhex(garbage), garbage)

    def test_batch_quote_escapes_backslashes_and_quotes(self):
        self.assertEqual(telegram_kit._batch_quote(r'back\slash "quote"'),
                          r'back\\slash \"quote\"')

    def test_batch_quote_rejects_a_newline(self):
        with self.assertRaises(ValueError):
            telegram_kit._batch_quote("line1\nline2")

    def test_detect_backend_prefers_keychain_on_macos(self):
        with mock.patch.object(telegram_kit, "IS_MACOS", True), \
                mock.patch.object(telegram_kit, "IS_WINDOWS", False), \
                mock.patch.object(telegram_kit.shutil, "which", return_value="/usr/bin/security"):
            self.assertEqual(telegram_kit._detect_backend(), "keychain")

    def test_detect_backend_prefers_dpapi_on_windows(self):
        with mock.patch.object(telegram_kit, "IS_MACOS", False), \
                mock.patch.object(telegram_kit, "IS_WINDOWS", True), \
                mock.patch.object(telegram_kit.shutil, "which", return_value="powershell.exe"):
            self.assertEqual(telegram_kit._detect_backend(), "dpapi")

    def test_detect_backend_falls_back_to_libsecret_on_linux(self):
        with mock.patch.object(telegram_kit, "IS_MACOS", False), \
                mock.patch.object(telegram_kit, "IS_WINDOWS", False), \
                mock.patch.object(telegram_kit.shutil, "which", return_value="/usr/bin/secret-tool"):
            self.assertEqual(telegram_kit._detect_backend(), "libsecret")

    def test_detect_backend_is_none_with_nothing_installed(self):
        with mock.patch.object(telegram_kit, "IS_MACOS", False), \
                mock.patch.object(telegram_kit, "IS_WINDOWS", False), \
                mock.patch.object(telegram_kit.shutil, "which", return_value=None):
            self.assertIsNone(telegram_kit._detect_backend())


class BackendLabelTests(unittest.TestCase):
    def test_available_and_label_reflect_the_detected_backend(self):
        with mock.patch.object(telegram_kit, "backend", lambda: "libsecret"):
            self.assertTrue(telegram_kit.available())
            self.assertEqual(telegram_kit.backend_label(), "Secret Service (libsecret)")

    def test_unavailable_when_nothing_is_detected(self):
        with mock.patch.object(telegram_kit, "backend", lambda: None):
            self.assertFalse(telegram_kit.available())
            self.assertEqual(telegram_kit.backend_label(), "none")

    def test_backend_probes_only_once_and_caches_the_result(self):
        telegram_kit.backend.cache_clear()
        try:
            with mock.patch.object(telegram_kit, "_detect_backend", return_value="keychain") as probe:
                self.assertEqual(telegram_kit.backend(), "keychain")
                self.assertEqual(telegram_kit.backend(), "keychain")
            probe.assert_called_once()
        finally:
            telegram_kit.backend.cache_clear()


class DpapiDirTests(unittest.TestCase):
    def test_defaults_to_appdata_when_set(self):
        with mock.patch.dict(os.environ, {"APPDATA": r"C:\Users\wes\AppData\Roaming"}):
            self.assertEqual(telegram_kit._default_dpapi_dir("other-app"),
                              pathlib.Path(r"C:\Users\wes\AppData\Roaming") / "other-app")

    def test_falls_back_to_home_when_appdata_is_unset(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("APPDATA", None)
            self.assertEqual(telegram_kit._default_dpapi_dir("other-app"),
                              pathlib.Path.home() / "AppData" / "Roaming" / "other-app")


def _fake_winreg(*, value=None, opening_fails=False):
    module = types.SimpleNamespace(HKEY_CURRENT_USER=object())

    class _Key:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def open_key(hive, path):
        if opening_fails:
            raise OSError("no such registry key")
        return _Key()

    module.OpenKey = open_key
    module.QueryValueEx = lambda key, name: (value, 1)
    return module


class LegacyWindowsTokenTests(unittest.TestCase):
    def test_false_on_non_windows_without_touching_the_registry(self):
        with mock.patch.object(telegram_kit, "IS_WINDOWS", False):
            self.assertFalse(telegram_kit.legacy_windows_env_token_present())

    def test_true_when_the_registry_still_holds_a_token(self):
        with mock.patch.object(telegram_kit, "IS_WINDOWS", True), \
                mock.patch.dict(sys.modules, {"winreg": _fake_winreg(value="fake-token")}):
            self.assertTrue(telegram_kit.legacy_windows_env_token_present())

    def test_false_when_the_stored_value_is_empty(self):
        with mock.patch.object(telegram_kit, "IS_WINDOWS", True), \
                mock.patch.dict(sys.modules, {"winreg": _fake_winreg(value="")}):
            self.assertFalse(telegram_kit.legacy_windows_env_token_present())

    def test_false_when_the_registry_key_does_not_exist(self):
        with mock.patch.object(telegram_kit, "IS_WINDOWS", True), \
                mock.patch.dict(sys.modules, {"winreg": _fake_winreg(opening_fails=True)}):
            self.assertFalse(telegram_kit.legacy_windows_env_token_present())


class CredentialStoreLibsecretAndKeychainTests(unittest.TestCase):
    """The keychain/libsecret argv shapes get/set/delete build, and that a
    non-zero exit or a raised exception both mean "no secret" rather than a
    crash — mirrors CredentialStoreTests but for the two backends that test
    class's dpapi-focused cases don't touch."""

    def test_libsecret_get_set_delete_argv(self):
        store = telegram_kit.CredentialStore("other-app")
        run = Recorder((0, "fake-token\n"), (0, ""), (0, ""))
        with pinned("libsecret", run):
            self.assertEqual(store.get("telegram_bot_token"), "fake-token")
            self.assertTrue(store.set("telegram_bot_token", "fake-token"))
            self.assertTrue(store.delete("telegram_bot_token"))
        get_argv, set_argv, delete_argv = (c[0] for c in run.calls)
        self.assertEqual(get_argv, ["secret-tool", "lookup", "service", "other-app",
                                     "account", "telegram_bot_token"])
        self.assertEqual(set_argv[:2], ["secret-tool", "store"])
        self.assertEqual(run.calls[1][1], "fake-token")  # secret travels on stdin, not argv
        self.assertEqual(delete_argv, ["secret-tool", "clear", "service", "other-app",
                                        "account", "telegram_bot_token"])

    def test_keychain_delete_argv(self):
        store = telegram_kit.CredentialStore("other-app")
        run = Recorder((0, ""))
        with pinned("keychain", run):
            self.assertTrue(store.delete("telegram_bot_token"))
        self.assertEqual(run.calls[0][0], ["security", "delete-generic-password",
                                            "-s", "other-app", "-a", "telegram_bot_token"])

    def test_a_nonzero_exit_reads_as_no_secret_not_a_crash(self):
        store = telegram_kit.CredentialStore("other-app")
        with pinned("keychain", Recorder((1, ""))):
            self.assertEqual(store.get("telegram_bot_token"), "")

    def test_a_raising_helper_reads_as_no_secret_not_a_crash(self):
        def exploding(argv, stdin=None):
            raise OSError("helper vanished")
        store = telegram_kit.CredentialStore("other-app")
        with pinned("keychain", exploding):
            self.assertEqual(store.get("telegram_bot_token"), "")
            self.assertFalse(store.set("telegram_bot_token", "fake-token"))
            self.assertFalse(store.delete("telegram_bot_token"))

    def test_setting_an_empty_value_deletes_instead_of_storing_blank(self):
        store = telegram_kit.CredentialStore("other-app")
        run = Recorder((0, ""))
        with pinned("keychain", run):
            self.assertTrue(store.set("telegram_bot_token", ""))
        self.assertEqual(run.calls[0][0][:2], ["security", "delete-generic-password"])


if __name__ == "__main__":
    unittest.main()
