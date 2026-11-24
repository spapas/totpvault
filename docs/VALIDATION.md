# Initial validation

Validated on 8 October 2026 (Europe/Athens), with Go 1.27.1.

## Automated checks

- `go test -race ./...`: passed. Fyne's software test driver exercises filtering, filtered selection, copying the selected account, preserving newer clipboard content, clipboard expiry and automatic locking.
- `go test -race ./...`: passed with the native desktop-driver dependencies enabled.
- `go vet ./...`: passed.
- `govulncheck ./...`: no reachable vulnerabilities and no vulnerable imported packages. The database also flags the unused `openpgp` package within `x/crypto`; this application imports only Argon2id and XChaCha20-Poly1305 from that module.
- `go mod verify`: passed.
- TOTP: all 18 RFC 6238 vectors, across SHA-1/SHA-256/SHA-512 and timestamps through 20,000,000,000; rollover countdown and URI validation checks passed.
- Vault: encrypted round trip, no plaintext account/password bytes on disk, wrong-password rejection, refusal to overwrite an existing vault at creation, lock behavior, tampered header/ciphertext rejection, truncated file rejection, nonce changes, password rotation, rejected invalid entries and stale-session write rejection passed.
- A software-rendered main-window screenshot was inspected at 720 × 520 with synthetic accounts using public RFC secrets. Labels, codes, buttons and countdown bars were legible without overlap.

## Limits

Linux amd64 and Windows amd64 GUI executables were compiled successfully, including the native Fyne/OpenGL driver. A native Linux desktop launch could not be verified in this execution environment because its X server sockets are restricted. The software-driven GUI checks above passed. Windows runtime behavior must also be checked on a Windows desktop; cross compilation alone does not establish it.

No independent cryptographic review, malicious-host testing, power-loss fault injection or real user secrets were part of these checks. The GitHub workflow is configured to repeat tests, static checks, vulnerability checks and builds on Linux and Windows after the repository is created.

## i18n (released in 1.0.0)

- New offline `internal/i18n` package: English source strings plus French,
  German, Italian, Spanish, Chinese (Simplified) and Greek tables, compiled
  in (no network, no new modules).
- Automated: key coverage across all languages, format-verb match per key,
  English fallback, singular/plural rules (incl. French 0-singular), backend
  error translation incl. wrapped `invalid account` / QR / clipboard errors.
- UI: OS language auto-detected at startup, switchable in Settings, persisted
  as a non-secret tag in app preferences; screens rebuild on switch.
  `go test` passes for `i18n`/`totp`/`vault`/`qrimg`; full Fyne UI tests and
  native builds run in CI (this environment has no C99/MinGW toolchain).

## Re-validation 1.1.0 / 1.2.0 — 7 November 2026 (Europe/Athens)

Go 1.27.1 windows/amd64, commit `84b83cb` (after the `1.2.0` bump).

- `go test -race ./...`: passed, all packages including `internal/ui`
  with the native desktop-driver dependencies enabled.
- `go vet ./...`: passed.
- `go mod verify`: passed (`all modules verified`).
- `govulncheck ./...`: not run locally; covered by CI on both platforms.
- Screenshots re-inspected: `docs/screenshots/main.png` shows the 1.2.0
  single-row toolbar (Add / Copy / Edit / Delete / Export + overflow),
  condensed code+countdown rows and `3 accounts - auto-lock after 5m idle`
  status; `docs/screenshots/login.png` shows the unlock screen. Both legible,
  no overlap.
- `1.1.0` fixes re-covered by tests: missing-toolbar-key regression test
  (`TestAllUIKeysTranslated`) passes; app/window icon set via embedded
  `icon.svg`.

## 2.0.0 Rust rewrite — 8 November 2026 (Europe/Athens)

Rust 1.99.1 windows/x86_64-msvc, after the `2.0.0` bump (Go archived).

- `cargo test --locked`: passed, all crates (totp/totp-vectors, vault
  round-trip/tamper/stale-write/interop, qrimg round-trip/rejects, i18n
  coverage, app filter/dup unit tests).
- `cargo fmt --check` / `cargo clippy --all-targets --locked -- -D warnings`:
  covered by CI on Windows/Linux/macOS (local toolchain lacks fmt/clippy).
- `cargo audit`: covered by CI (0 vulnerabilities on 2026-11-07 baseline).
- `cargo build --locked --release -p totpvault`: Windows binary builds
  (~7 MB class, stripped + LTO).
- Interop: `vault::tests::go_interop_fixture` reads the archived Go fixture
  (`interop/go-vault.dat`); `cargo run -p totpvault-vault --example gen`
  rewrites `interop/rust-vault.dat`.
- Release packaging: `scripts/package_release.py` validates `MZ`/`ELF`/
  `Mach-O` magic and produces Windows ZIP + Linux/macOS tar.gz + `SHA256SUMS`.
- Manual GUI walkthrough of the Rust UI per this file is still pending; the
  workflow (add/import/QR/copy/lock/settings/about) mirrors 1.x.

## 3.0.0 — 15 November 2026 (Europe/Athens)

Rust 1.99.1 windows/x86_64-msvc, after the `3.0.0` bump (vault format v1 unchanged).

- `cargo test --locked`: passed, all crates (15 app tests incl. QR render,
  strength, pins, backup round-trip, clock, font, tray icon/close-to-tray;
  6 i18n incl. new-key coverage; totp/vault/qrimg suites incl. Go interop).
- `cargo fmt --check` / `cargo clippy --all-targets --locked -- -D warnings`:
  passed locally on Windows; repeated by CI on all three platforms.
- `cargo audit`: no vulnerabilities (3 pre-existing unmaintained warnings:
  `zbus_names`/`zvariant`/`zvariant_derive`).
- New UI surface since 2.0.0 (export QR, backup + auto-`.bak`, pins,
  copy-on-select, font/compact/contrast, focus-lock, strength meter,
  Caps-Lock warning, clock warning, next-code preview, tray icon) is covered
  by unit tests for the pure helpers; manual desktop walkthrough (tray
  show/hide/quit on Windows/Linux/macOS, QR scan, backup restore) is pending
  and should be done against the release binaries.

## 3.1.0 — 15 November 2026 (Europe/Athens)

Patch release on vault format v1 (unchanged): vector-drawn star pin
(instead of tofu-prone ★/☆) and a real toggle fix — the card-level
interact used to swallow the pin clicks, now covered by a headless
click-regression test.

- `cargo test --locked`: passed (18 app tests incl. star geometry +
  click-delivery regression; 6 i18n; totp/vault/qrimg incl. Go interop).
- `cargo fmt --check` / `cargo clippy --all-targets --locked -- -D warnings`:
  passed locally on Windows; repeated by CI on all three platforms.
- `cargo audit`: no new advisories.
- Pin toggle manually verified on Windows (star fills, card jumps on top,
  status confirms pin/unpin).

## 3.2.0 — 24 November 2026 (Europe/Athens)

Minor release on vault format v1 (unchanged): UI/UX pass (per-card copy,
keyboard flow, search, onboarding, grouped settings) and hostile-input
robustness tests; dependency refresh (`rand` 0.10, `qrcode` 0.15) and the
single-instance lock moved to `std::fs::File::try_lock`, dropping `fs2`.

- `cargo test --locked`: passed (21 app, 6 i18n, 4 vault, 6 totp, 6 qrimg
  incl. Go interop and QR round-trip).
- `cargo fmt --check` / `cargo clippy --all-targets --locked -- -D warnings`:
  passed locally on Windows; repeated by CI on all three platforms.
- `cargo audit`: no vulnerabilities; only the ignored unmaintained zbus
  advisories (`ksni` still pins `zbus` 5).
- `cargo build --locked --release -p totpvault`: passed (Windows MSVC,
  Rust 1.100.0).
- Manual desktop walkthrough of the new UI/UX pass (tray, QR scan against a
  phone, backup restore) still pending against the release binaries.
