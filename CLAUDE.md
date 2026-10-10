# CLAUDE.md

## Cross-platform

Code must run on macOS, Linux, and Windows (paths, separators, shell commands, line
endings, `$HOME` vs `%USERPROFILE%`, file locking, symlinks, terminal/ANSI). Guard
platform-specific code and say so.

- Reuse the shared platform helpers first: `src/telegram_kit/__init__.py` (`IS_WINDOWS`, `IS_MACOS`).
- Text I/O always passes `encoding="utf-8"` (Windows defaults to cp1252).
- Windows is verified by CI's `windows-latest` job, not locally; POSIX-only tests are
  skipped on Windows (`os.name == "nt"`).
