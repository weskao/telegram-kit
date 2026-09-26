# telegram-kit

Secure Telegram Bot API notifications for any Python project. Stdlib only —
no dependencies, no vendoring.

```python
import telegram_kit

telegram_kit.notify("build finished", service="my-app", chat_id="123456789")

store = telegram_kit.CredentialStore("my-app")
token = telegram_kit.read_hidden("Telegram bot token (hidden): ")
if token and store.set("telegram_bot_token", token):
    print("stored as", telegram_kit.mask_secret(token))
```

## Install

```bash
uv add "telegram-kit @ git+https://github.com/weskao/telegram-kit@v0.1.0"
```

Pin to a tag. Bumping the tag and re-running
`uv lock --upgrade-package telegram-kit` is how every project using this kit
picks up a fix — no file to copy, no diff to reapply.

## What it guarantees, whichever project uses it

- **No plaintext fallback.** `CredentialStore` writes to the OS credential
  store (macOS Keychain, Linux Secret Service, Windows DPAPI). With none
  available, it refuses to store rather than falling back to a plaintext
  file or home-rolled obfuscation.
- **Each caller gets its own namespace.** `CredentialStore(service)` keys
  every item under that service name, so two projects on the same machine
  never collide.
- **Credentials never touch argv or the process list** — batch-mode/stdin
  paths are used for every backend.
- **Owner-only atomic writes** (`write_private`) for anything that must live
  on disk, on POSIX and Windows alike.

## API

| Function | Purpose |
|---|---|
| `CredentialStore(service, dpapi_dir=None)` | Get/set/delete a secret in the OS store. |
| `resolve_credentials(token, chat_id, environ=None)` | Configured value, else `TG_BOT_TOKEN`/`TG_CHAT_ID`. |
| `send_message(token, chat_id, text, timeout=10)` | One `sendMessage` call. `False` on any failure. |
| `notify(text, service, chat_id="", token_key=..., store=None)` | Resolve + send in one call. |
| `read_hidden(prompt, ask=None)` | Hidden input; `None` if the terminal can't hide it. |
| `mask_secret(secret)` | `********` plus at most the last 4 characters. |
| `write_private(target, content)` | Atomic, owner-only file write. |

## Develop

```bash
uv run python -m unittest discover -s tests -t . -v
uv run ruff check .
```
