# Archived Go implementation (v1.x)

This directory preserves the original Go + Fyne implementation of TOTP Vault,
up to v1.2.0. It is **read-only history** — no CI runs here and no further
development happens on this code.

- `cmd/totpvault` — entry point (`--vault`, single-instance lock).
- `internal/totp` — RFC 6238, URI parse/format.
- `internal/vault` — Argon2id + XChaCha20-Poly1305 vault format v1.
- `internal/qrimg` — offline QR decode.
- `internal/ui` — Fyne desktop UI.
- `internal/i18n` — EN/FR/DE/IT/ES/ZH/EL tables.
- `interop-gen` — fixture generator (was `rust/interop/gen`, writes
  `interop/go-vault.dat`; run from the repo root, needs Go + the old module).

The active implementation since **v2.0.0** is pure Rust at the repo root
(`Cargo.toml`, `crates/`, `app/`, `interop/`). The vault format v1 is
unchanged, so v1 vaults open directly in v2.
