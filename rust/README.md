# TOTP Vault — Rust port (`rust/`)

Pure-Rust port of the Go TOTP Vault, same vault format v1, same security
properties. The Go app is untouched; both unlock each other's `vault.dat`.

## Layout

| Crate | Mirrors | Notes |
|---|---|---|
| `crates/totp` | `internal/totp` | RFC 6238, URI parse/format, zero deps beyond crypto |
| `crates/vault` | `internal/vault` | Argon2id + XChaCha20-Poly1305, atomic replace, fingerprint |
| `crates/qrimg` | `internal/qrimg` | PNG/JPEG + QR decode (`rqrr`), same limits |
| `crates/i18n` | `internal/i18n` | EN/DE/EL/ES/FR/IT/ZH, tables generated from Go |
| `app` (`totpvault-rs`) | `internal/ui` + `cmd/totpvault` | `egui`/`eframe` GUI on the **glow/OpenGL** renderer, `arboard` clipboard, `fs2` lock |

`interop/` holds cross-compatibility fixtures: `go-vault.dat` was written by
the real Go code (`gen/main.go`), `rust-vault.dat` by this port
(`cargo run -p totpvault-vault --example gen`). Both sides read both files;
`vault::tests::go_interop_fixture` locks it in.

## Build

MSVC toolchain required on Windows (uses the system linker):

```powershell
scoop install rust-msvc   # or rustup: stable-x86_64-pc-windows-msvc
cd rust
cargo test                # 20 tests: RFC vectors, vault round-trip/tamper,
                          # QR round-trip, i18n coverage, UI filter/dup logic
cargo run -p totpvault-rs [-- --vault PATH]
```

Linux: `cargo test` / `cargo run -p totpvault-rs` (needs OpenGL + X11/Wayland
dev libs for `eframe`, same class of deps as Fyne).

## Intentional differences from the Go app

- GUI is `egui` immediate-mode with its own modern design (nothing like Fyne):
  teal brand accent, Segoe UI + Consolas, theme switcher (System/Light/Dark)
  persisted in prefs, account cards with issuer avatars and countdown rings,
  double-click to copy, padlock mark on login.
- Language preference lives in `TotpVault/prefs.json` under the OS config
  dir (Fyne preferences are not shared); auto-detectRule is identical.
- CJK rendering needs a system CJK font (Windows `msyh.ttc`, Linux Noto CJK);
  otherwise CJK glyphs fall back to tofu. Latin/Greek are always fine.
- No embedded tray icon yet (Go embeds `icon.svg`).
- `cargo audit` replaces `govulncheck` in CI: **0 vulnerabilities** (2026-11-07;
  only 4 unmaintained warnings on transitive Linux D-Bus crates).
- Release binary builds (`cargo build --release -p totpvault-rs`, ~7 MB,
  `windows_subsystem`, stripped + LTO + `opt-level="z"`) and
  the GUI launches and runs (20 s smoke test, lock file held, no crash).
- Manual GUI walkthrough per `docs/VALIDATION.md` is still pending for this port.

## Regenerating tables / fixtures

```powershell
python gen_tables.py            # from crates/i18n: Go i18n/*.go -> tables.rs
cargo run -p totpvault-vault --example gen   # rewrite rust-vault.dat
go run ./rust/interop/gen       # from repo root: rewrite go-vault.dat
```
