# AGENTS.md — Instructions for coding agents

This repo is **TOTP Vault**: a small offline TOTP authenticator for
Windows + Linux + macOS, written in Rust with `egui` (glow/OpenGL). No server,
no network, no telemetry. The Go/Fyne 1.x implementation is archived read-only
in `archived/go/`; do not modify it except to fix its README.

Read `ARCHITECTURE.md` and `SECURITY.md` before changing `crates/totp`,
`crates/vault` or `app`. Security properties here are load-bearing, not style.

## Layout

| Path | What lives there |
|---|---|
| `app/src/main.rs` | Entry point: `--vault` flag, default path, `0700` dir creation, single-instance `fs2` lock, then `eframe::run_native` |
| `app/src/app.rs` | egui controller: login → main list → dialogs, 500 ms repaint tick (codes, clipboard expiry, auto-lock), `Paste QR` via `arboard` image clipboard + `qrimg` + `parse_uri` |
| `app/src/prefs.rs` | Non-secret `language` + `theme` in `TotpVault/prefs.json` (OS config dir) |
| `crates/totp` | RFC 6238 `code()`, `normalize()`, `parse_uri()`/`provisioning_uri()` — pure, no I/O |
| `crates/qrimg` | Offline QR decode `decode_bytes()` (clipboard PNG/JPEG → URI text) — pure, no I/O, no clipboard calls; caller must still run `totp::parse_uri` |
| `crates/vault` | Argon2id + XChaCha20-Poly1305 file format, `Session::create/unlock/save/change_password`, atomic replace, fingerprint anti-stale-write |
| `crates/i18n` | Offline UI translations (EN source; FR/DE/IT/ES/ZH/EL), OS language detect; `tables.rs` generated from `archived/go` via `gen_tables.py` |
| `interop/` | Cross-compat fixtures `go-vault.dat` / `rust-vault.dat` (same password); `vault::tests::go_interop_fixture` locks it in |
| `docs/VALIDATION.md` | What was manually validated |
| `scripts/package_release.py` | CI packaging: validates `VERSION` + `MZ`/`ELF`/`Mach-O` magic, zips/tarballs binaries + docs, writes `SHA256SUMS` |
| `.github/workflows/build.yml` | Matrix build (ubuntu-24.04, windows-latest, macos-latest): fmt → test → clippy → audit → release build → draft/publish release |

## Commands (verified from CI + README)

```sh
cargo fmt --check
cargo test --locked

# Full suite — always run before touching crypto/UI logic
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings

# Vulnerability check (same tool CI uses)
cargo install cargo-audit --locked
cargo audit
```

Build natively per OS (cross-compiling GUI is NOT supported):

```powershell
# Windows, Rust stable MSVC
cargo test --locked
cargo build --locked --release -p totpvault
```

```sh
# Linux (Ubuntu/Debian)
sudo apt-get install gcc pkg-config libgl1-mesa-dev libegl1-mesa-dev xorg-dev libwayland-dev libxkbcommon-dev
cargo test --locked
cargo build --locked --release -p totpvault
```

```sh
# macOS (Apple Silicon, Xcode CLT)
cargo test --locked
cargo build --locked --release -p totpvault
```

Regenerate fixtures/tables:

```sh
cargo run -p totpvault-vault --example gen   # rewrite interop/rust-vault.dat
python3 crates/i18n/gen_tables.py            # archived/go tables -> tables.rs
```

## Rules — do not break these

1. **Fail closed.** Unknown vault bytes, unknown URI params (`HOTP`, extra query keys),
   bad Base32, mismatched issuer/label → return error. Never guess or migrate silently.
   See `totp::normalize` limits (name ≤256, secret ≤1024 chars / ≥10 bytes, 6/8 digits,
   period 1–300, SHA1/256/512) and `vault` limits (8 MiB file, 10 000 accounts).
   QR pastes: PNG/JPEG ≤5 MiB, ≤4000 px/side, ≤16 M px, single symbol; decoded text
   still goes through `parse_uri` — never save decode output directly.
2. **Crypto is version-pinned.** Argon2id `t=3, m=64MiB, p=4, keylen=32` and
   XChaCha20-Poly1305 with 16-byte salt + 24-byte nonce are fixed by format v1
   (`TOTPVLT\x01`). Do not make KDF params configurable from file headers.
   Header (48 B) is AEAD additional data. Fresh RNG nonce on every save.
3. **No plaintext on disk.** `vault.dat` holds header + ciphertext+tag only.
   Writes: temp file in same dir → flush → rename → dir sync where supported.
   `create` uses exclusive creation (never overwrite). `save/change_password` rejects
   stale fingerprints (`Changed`).
4. **Memory hygiene (best-effort).** `zeroize` keys/plaintext after use, drop/zero
   sessions on lock, clear password entries after submit. Do not log secrets,
   passwords, URIs, or vault bytes. Do not add telemetry, network calls, or caching
   of secrets outside `Session`.
5. **UI session discipline.** All mutations go through `save()` →
   `Session::save()` → `apply_filter()`. Background KDF/QR results are ignored
   when locked meanwhile; edit/delete also verify the account index still holds
   the same account. Activity = form/search/selection/button only; tick must NOT
   reset idle timers. Clipboard clears after 15 s only if content still equals
   copied code or URI. Settings (idle 1–15 min, hide-codes, theme, language) are
   per-session except persisted non-secret language/theme prefs, defaults 5 min /
   visible / system.
6. **Keep it offline.** No new dependencies that dial network, no auto-update,
   no camera capture, no bulk export/import. Pinned offline exceptions: `arboard`
   (OS clipboard), `fs2` (file lock), `rqrr` (QR decode), `eframe/glow` (GUI).
   If you add a dep, keep `Cargo.lock` committed and ensure `cargo audit` stays clean.
7. **Permissions.** POSIX vault `0600`, dirs `0700`. Windows/macOS rely on profile
   directory ACLs — don't chmod around them.

## Change checklist

- [ ] `cargo fmt --check` + `cargo test --locked` + `cargo clippy --all-targets --locked -- -D warnings` + `cargo audit` pass (all three OS in CI, at least local OS here)
- [ ] New validation covered in tests (RFC vectors for TOTP, round-trip/tamper/stale-write/interop for vault, QR round-trip + reject paths for qrimg)
- [ ] `SECURITY.md` updated if format, KDF, locking, or threat model changed
- [ ] `docs/VALIDATION.md` note if manual GUI/clock/lock behavior changed
- [ ] `VERSION` untouched unless doing a release (format `X.Y.Z`, tag `vX.Y.Z` must match)
- [ ] Never modify `archived/go/` implementation files (README-only)
