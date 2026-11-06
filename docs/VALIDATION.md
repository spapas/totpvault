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

## i18n (unreleased)

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
