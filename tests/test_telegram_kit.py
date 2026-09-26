"""The reusable Telegram kit other projects import. Synthetic credentials only."""
import getpass
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
import warnings
from unittest import mock

import telegram_kit

ROOT = pathlib.Path(__file__).resolve().parents[1]


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
            cwd=ROOT, env={"PYTHONPATH": str(ROOT / "src")},
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


if __name__ == "__main__":
    unittest.main()
