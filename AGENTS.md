# AGENTS.md — Instructions for coding agents

This repo is **TOTP Vault**: a small offline TOTP authenticator for Windows + Linux,
written in Go with Fyne (GUI, CGO + OpenGL). No server, no network, no telemetry.

Read `ARCHITECTURE.md` and `SECURITY.md` before changing `internal/totp`, `internal/vault`
or `internal/ui`. Security properties here are load-bearing, not style.

## Layout

| Path | What lives there |
|---|---|
| `cmd/totpvault/main.go` | Entry point: `--vault` flag, default path, `0700` dir creation, single-instance `flock`, then `ui.Run(abs)` |
| `internal/totp/totp.go` | RFC 6238 `Code()`, `Normalize()`, `ParseURI()` — pure, no I/O |
| `internal/qrimg/qrimg.go` | Offline QR decode `DecodeBytes()` (clipboard PNG/JPEG → URI text) — pure, no I/O, no clipboard calls; caller must still run `totp.ParseURI` |
| `internal/vault/vault.go` | Argon2id + XChaCha20-Poly1305 file format, `Create/Unlock/Save/ChangePassword`, atomic replace, fingerprint anti-stale-write |
| `internal/ui/ui.go` + `theme.go` | Fyne controller: login → main list → dialogs, 250 ms tick (codes, clipboard expiry, auto-lock), `Paste QR` via OS image clipboard + `qrimg` + `ParseURI` |
| `docs/VALIDATION.md` | What was manually validated on 2026-10-08 |
| `scripts/package_release.py` | CI packaging: validates `VERSION` + `MZ`/`ELF` magic, zips/tarballs binaries + docs, writes `SHA256SUMS` |
| `.github/workflows/build.yml` | Matrix build (ubuntu-24.04, windows-latest): test → vet → govulncheck → build → draft/publish release |

## Commands (verified from CI + README)

```sh
go mod download
go mod verify

# Full suite — always run before touching crypto/UI logic
go test -race ./...
go vet ./...

# Vulnerability check (same version CI pins)
go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
govulncheck ./...
```

Build natively per OS (cross-compiling without matching C toolchain is NOT supported):

```bat
:: Windows CMD, Go >= 1.26 + 64-bit MinGW-w64 gcc
set CGO_ENABLED=1
go test ./internal/totp ./internal/vault
go build -trimpath -ldflags="-s -w -H=windowsgui" -o dist\totpvault.exe ./cmd/totpvault
```

```sh
# Linux (Ubuntu/Debian), Go >= 1.26
sudo apt-get install gcc pkg-config libgl1-mesa-dev xorg-dev libwayland-dev libxkbcommon-dev
go test -race ./...
go build -trimpath -ldflags="-s -w" -o dist/totpvault ./cmd/totpvault
```

Tags: `ui_test.go` uses `-tags ci` for the Fyne software test driver in headless CI.
Native runs use the real desktop driver.

## Rules — do not break these

1. **Fail closed.** Unknown vault bytes, unknown URI params (`HOTP`, extra query keys),
   bad Base32, mismatched issuer/label → return error. Never guess or migrate silently.
   See `totp.Normalize` limits (name ≤256, secret ≤1024 chars / ≥10 bytes, 6/8 digits,
   period 1–300, SHA1/256/512) and `vault` limits (8 MiB file, 10 000 accounts).
   QR pastes: PNG/JPEG ≤5 MiB, ≤4000 px/side, ≤16 M px, single symbol; decoded text
   still goes through `ParseURI` — never save decode output directly.
2. **Crypto is version-pinned.** Argon2id `t=3, m=64MiB, p=4, keylen=32` and
   XChaCha20-Poly1305 with 16-byte salt + 24-byte nonce are fixed by format v1
   (`TOTPVLT\x01`). Do not make KDF params configurable from file headers.
   Header (48 B) is AEAD additional data. Fresh `crypto/rand` nonce on every save.
3. **No plaintext on disk.** `vault.dat` holds header + ciphertext+tag only.
   Writes: temp file in same dir → `Sync` → `Rename` → dir `Sync` where supported.
   `Create` uses `O_CREATE|O_EXCL` (never overwrite). `Save/ChangePassword` rejects
   stale fingerprints (`ErrChanged`).
4. **Memory hygiene (best-effort).** `clear()` keys/plaintext after use, `Session.Lock()`
   zeroes key + accounts, password entries cleared after submit. Do not log secrets,
   passwords, URIs, or vault bytes. Do not add telemetry, network calls, or caching
   of secrets outside `Session`.
5. **UI session discipline.** All mutations go through `controller.save()` →
   `Session.Save()` → `filter()`. Dialogs capture `session` pointer and abort if
   `c.session != session` (locked meanwhile). Activity = form/search/selection/button
   only; countdown/mouse-move must NOT reset `lastActivity`. Clipboard clears after
   15 s only if content still equals copied code. Settings (idle 1–15 min) are
   per-session, default 5 min.
6. **Keep it offline.** No new dependencies that dial network, no auto-update,
   no QR/camera, no bulk export. Pinned offline exceptions: `golang.design/x/clipboard`
   (OS image clipboard, Cgo-free) + `piglig/go-qr/v2` (pure decode, zero runtime deps).
   If you add a dep, keep `go.mod` tidy and ensure `govulncheck` stays clean.
7. **Permissions.** POSIX vault `0600`, dirs `0700`. Windows relies on profile ACLs —
   don't chmod around it.

## Change checklist

- [ ] `go test -race ./...` + `go vet ./...` pass (both OS in CI, at least local OS here)
- [ ] New validation covered in `*_test.go` (RFC vectors for TOTP, round-trip/tamper/stale-write for vault, QR round-trip + reject paths for qrimg)
- [ ] `SECURITY.md` updated if format, KDF, locking, or threat model changed
- [ ] `docs/VALIDATION.md` note if manual GUI/clock/lock behavior changed
- [ ] `VERSION` untouched unless doing a release (format `X.Y.Z`, tag `vX.Y.Z` must match)
