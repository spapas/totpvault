# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions are `X.Y.Z` and release tags are `vX.Y.Z` (must match `VERSION`).

## [Unreleased]

## [1.0.0] - 2026-11-06

### Added

- Interface languages: English (source), French, German, Italian, Spanish,
  Chinese (Simplified) and Greek. OS language auto-detected, switchable in
  Settings, persisted in app preferences. Backend validation errors are shown
  translated via the new offline `internal/i18n` package (no new
  dependencies; `go-locale` promoted from indirect to direct).

## [0.3.0] - 2026-11-06

### Added

- Alphabetical account sorting; search status shows `showing X of Y`.
- Duplicate protection on save (same name+issuer, or same secret with identical settings).
- Optional `Hide codes until selected` in Settings (select-to-reveal, skips HMAC for hidden rows).
- Enter copies the selected code; countdown goes bold under 6 seconds.
- About dialog with vault path, backup reminder, clock note and shortcuts.
- `Show secret` toggle in Add/Edit; delete confirm shows issuer and permanent-loss warning.
- Startup failures also print to stderr with non-zero exit (headless-safe).

### Fixed

- Stale-index guards on edit/delete (abort instead of wrong overwrite/panic).
- Lock wipes dialog secrets via `clearOnLock` and untracks dismissed dialogs.
- QR decode checks dimensions via `DecodeConfig` before full decode.
- Auto-lock wall-clock backstop for sleep/hibernate; shutdown drains queued KDF work.
- Failed QR pastes no longer reset selection; invalid idle minutes rejected.
- Deleted-vault save maps to `ErrChanged`; `ChangePassword` releases old key slice.
- Unreadable vault path shows Retry/Quit; vault dir tightened to `0700` on POSIX.
- Ticker relaxed to 500 ms (same UX, less HMAC churn on large vaults).
- New edge tests: TOTP validation branches, vault size/account limits and password policy.

## [0.2.1] - 2026-10-15

### Added

- **Export**: copy a selected account's `otpauth://totp/...` provisioning URI
  to the clipboard for import in another app. Copies only after confirmation
  and the clipboard clears after 15 seconds if unchanged.
- Scoop install instructions for Windows (`README.md`).

### Fixed

- `ParseURI`: correctly handle `%3A`-encoded `issuer:name` separators in the
  label and keep `issuer`/`label` mismatch checks fail-closed.

## [0.2.0] - 2026-10-10

### Added

- **Paste QR**: import a TOTP account straight from a QR screenshot in the OS
  clipboard (`Paste QR` button). The image is decoded fully offline and the
  enclosed `otpauth://totp/...` URI goes through the existing validation —
  anything else is rejected and nothing is saved.
- New `internal/qrimg` package: pure offline QR decode (PNG/JPEG, ≤5 MiB,
  ≤4000 px/side, ≤16 M pixels, single symbol) with round-trip + reject tests.
- New pinned offline dependencies (no network): `golang.design/x/clipboard`
  `v0.11.0` (OS image clipboard, Cgo-free) and `github.com/piglig/go-qr/v2`
  `v2.6.0` (zero-runtime-dep QR decode).
- Docs: `README.md` (Paste QR usage), `SECURITY.md` (QR paste threat notes),
  `ARCHITECTURE.md` (paste flow + `qrimg`), `AGENTS.md` (limits + deps).

## [0.1.2] - 2026-10-08 and earlier

Changelog starts at `0.2.0`; `0.1.0`–`0.1.2` were the initial releases
(offline encrypted vault, RFC 6238 codes, Fyne desktop UI, CI-built
Windows/Linux binaries). See `docs/VALIDATION.md` for the initial checks.
