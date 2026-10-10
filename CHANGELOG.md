# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions are `X.Y.Z` and release tags are `vX.Y.Z` (must match `VERSION`).

## [Unreleased]

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
