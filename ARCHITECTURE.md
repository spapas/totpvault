# ARCHITECTURE.md

## 1. What this is

TOTP Vault is an **offline desktop authenticator** (Windows + Linux + macOS,
Apple Silicon + x86-64). One encrypted file (`vault.dat`) holds all TOTP
accounts. One Rust binary does everything: file handling, crypto, code
generation, GUI.

Design goals: small surface, fail closed, no network, no recovery backdoor.
Non-goals: camera capture, bulk export/import, sync, browser integration,
mobile. Single-account URI import/export and single QR screenshots pasted from
the clipboard are implemented.

v2.0.0 is a pure-Rust rewrite (`egui`) of the former Go/Fyne app (1.x,
preserved in `archived/go/`). Vault format v1 is unchanged: v1 and v2 unlock
each other's `vault.dat`.

```
┌─────────────┐   --vault path    ┌──────────────┐
│ app/main.rs  │ ────────────────▶ │ app/app.rs   │  egui controller
│ default path │  .dat.lock file   │ TotpApp      │ ─┐
│ 0700 dir     │  fs2 lock         └──────────────┘  │
└─────────────┘                                     │ uses
        │                                           ▼
        │ default path                ┌────────────────────┐
        │  Win: %APPDATA%\TotpVault\  │ crates/vault       │  Argon2id +
        │  Lin: ~/.local/share/      │ Session            │  XChaCha20-Poly1305
        │  Mac: ~/Library/App Supp/  └────────────────────┘
        │       TotpVault/vault.dat              │ encrypts []Account
        │                                        ▼
        └────────────────────────────▶┌────────────────────┐
                                      │ crates/totp        │  RFC 6238 pure
                                      │ Account/Code/URI   │  no I/O
                                      └────────────────────┘
```

## 2. Entry point — `app/src/main.rs`

1. Parses `--vault`; if empty resolves OS default
   (`dirs::data_dir()` + `TotpVault/vault.dat`; Windows `%APPDATA%`, Linux
   `$XDG_DATA_HOME` or `~/.local/share`, macOS `~/Library/Application Support`).
2. `create_dir_all` + `0700` on Unix.
3. `fs2::FileExt::try_lock_exclusive` on `vault.dat.lock` — second instance
   shows a fatal dialog and exits.
4. Loads language/theme prefs, then `eframe::run_native("TOTP Vault", …)`.
   `#![windows_subsystem = "windows"]` keeps double-click launches console-free;
   fatal startup errors also print to stderr plus a Win32 `MessageBoxW`.

No crypto, no TOTP logic here. Only path + single-instance guard.

## 3. TOTP core — `crates/totp` (pure)

`Account{name, issuer, secret, digits, period, algorithm}` — JSON-serializable,
also the vault payload unit.

- `normalize(a)` — canonicalizes (trim, uppercase secret/algorithm, strip
  whitespace + `=` padding, defaults `SHA1/6/30`) then validates:
  name required ≤256 B, issuer ≤256 B, digits ∈ {6,8}, period 1–300,
  algorithm ∈ {SHA1,SHA256,SHA512}, secret ≤1024 chars and valid Base32
  decoding to ≥10 bytes. Returns error otherwise.
- `code(&account, now_unix)` — re-normalizes, rejects pre-epoch clocks,
  HMAC-SHA* over 8-byte big-endian `floor(unix/period)`, dynamic truncation,
  `mod 10^digits`, zero-padded. Returns `(code, secondsRemaining)`.
- `provisioning_uri(&account)` — validates and formats one account as an
  `otpauth://totp/...` URI.
- `parse_uri(raw)` — accepts **only** `otpauth://totp/...` (≤8192 chars, no
  userinfo/fragment). Rejects duplicate params and any query key outside
  `{secret, issuer, algorithm, digits, period}` — so `HOTP`, `lock`, `image`,
  etc. fail. Handles `label = [issuer:]name`, checks issuer/label match,
  then delegates to `normalize`.

No filesystem, no clock source beyond the passed Unix time, no randomness.

## 4. Vault — `crates/vault`

### 4.1 Format v1 (fixed, see `SECURITY.md`)

| Offset | Size | Content |
|---|---|---|
| 0–7 | 8 | magic `TOTPVLT` + version `0x01` |
| 8–23 | 16 | Argon2id salt (`rand` at create / password change) |
| 24–47 | 24 | XChaCha20-Poly1305 nonce (fresh `rand` **every save**) |
| 48+ | var | `seal(plaintext JSON {accounts:[...]}, additionalData=header)` = ciphertext + 16 B tag |

KDF pinned: `argon2id(t=3, m=64MiB, p=4, keylen=32)`.
KDF params are **not** read from the file — a hostile header cannot tune CPU/RAM.
Header is AEAD additional data, so salt/nonce/magic tampering fails auth.

Limits enforced on read and write: file ≤8 MiB, accounts ≤10 000, every account
re-validated via `totp::normalize` after decrypt.

### 4.2 Session lifecycle

```
Session::create(path, pw) ── O_EXCL, never overwrites ─▶ Session{key, salt, fingerprint=sha256(file)}
Session::unlock(path, pw) ── derive → open → normalize ─▶ Session{key, salt, accounts, fingerprint}
session.save(accounts) ── normalize → encrypt(fresh nonce) → replace() ─▶ update accounts+fingerprint
session.change_password(pw) ── new salt+key → encrypt → replace() ─▶ swap key/salt (old key zeroized)
Session zeroized on lock/drop via zeroize
```

- `check_password`: ≥12 runes, ≤1024 bytes.
- `read()`: rejects oversize; `replace()`: re-reads file, compares `sha256`
  to session fingerprint → `ErrChanged` on external modification;
  writes temp file in same dir → flush → rename → best-effort dir sync.
  New vault creation uses exclusive creation.
- `encrypt()`: `serde_json` → seal, zeroes plaintext best-effort; rejects
  oversize output.
- Errors: `Authentication` (wrong pw or tamper — deliberately ambiguous),
  `Changed`, `Locked`, plus descriptive format/validation errors.

`interop/` holds cross-compatibility fixtures: `go-vault.dat` was written by
the archived Go code, `rust-vault.dat` by `cargo run -p totpvault-vault
--example gen`. Both sides read both files; `vault::tests::go_interop_fixture`
locks it in.

## 5. UI — `app/src/app.rs` + `prefs.rs`

Single `TotpApp` struct owns everything per window. `egui` immediate-mode;
single UI thread; KDF and QR-clipboard work run on background threads and
report back via channel.

### 5.1 Screens

Screens render through `totpvault-i18n`: English message IDs with FR/DE/IT/ES/
ZH/EL tables, plural-aware status lines, translated backend errors at the
display boundary (`err_text`). `totp`/`vault`/`qrimg` keep returning English
errors — translation never alters validation.

- `TotpApp::new(cc, path, lang, theme)` — installs fonts (Segoe UI + Consolas
  on Windows, Noto Sans on Linux, system fallback on macOS; CJK served on
  demand by the `system_fonts` provider), applies teal theme, starts at login.
- Login — create vs unlock decided by path metadata; password entries,
  optional confirm + 12-char hint on create. Submit clears entries, shows
  "Deriving encryption key…", derives Argon2id in a background thread, then
  back to the UI thread: error → message; success → main screen.
- Main — search entry + toolbar (Add / Copy / Edit / Delete / Export + ⋯ menu
  for Import / Paste QR / Settings / About / Lock) + scrollable account cards.
  Cards: avatar (issuer initial), name + issuer, monospace code + countdown
  ring (red at ≤5 s). Click selects, double-click copies. Enter / Ctrl+C
  copies the selected code when no text field or dialog owns the keystroke.
- Dialogs: account add/edit (validates via `normalize`; edit verifies the
  index still holds the same account), import URI (`parse_uri`), export
  confirm (copies URI, 15 s expiry), delete confirm, settings (idle 1/2/5/10/
  15 min + hide-codes + theme + language + optional password change), about
  (vault path, backup reminder, clock note).

### 5.2 Invariants

- **All writes via `save(accounts)`** → `session.save` → reload accounts → `apply_filter`.
- **Stale-session guard:** background results are ignored when
  `session.is_none()` (user locked meanwhile); edit/delete verify the index
  still holds the same account.
- **Secrets cleared:** password/secret fields `take()`n before KDF; dialogs
  drop secrets on close; `lock()` clears clipboard + accounts + selection.
- **`touch()` discipline:** only explicit actions (typing, selection, button
  handlers) reset the idle timer. Ticks never do.
- **`tick()`:** poll background channel → expire clipboard (clear only if OS
  clipboard still equals copied code/URI) → auto-lock when monotonic **or**
  wall-clock idle elapsed → else repaint at 500 ms.
- **`lock()`:** drop session, zero accounts, clear selection/search/clipboard,
  back to login.
- **`apply_filter()`:** unselect, rebuild visible by case-insensitive
  name+issuer substring, sort alphabetically (name, then issuer), refresh status.
- **`save()`:** `duplicate_error()` rejects same name+issuer or same
  secret-with-identical-settings before `session.save`.
- **`paste_qr()`:** `touch()`, status "reading QR…", background thread:
  `arboard` image → PNG bytes → `qrimg::decode_bytes` → `totp::parse_uri` →
  back to UI thread (`save(append)`). See `crates/qrimg` limits
  (PNG/JPEG, ≤5 MiB, ≤4000 px/side, ≤16 M px, text ≤8192 chars, single symbol).
- Prefs (`prefs.rs`): non-secret `language` + `theme` (`system/light/dark`) in
  `TotpVault/prefs.json` under the OS config dir. Never stores secrets.

## 6. QR clipboard import — `crates/qrimg`

Pure offline bridge between image bytes and URI text: size limits, dimension
pre-check, full decode (PNG/JPEG via `image`, QR via `rqrr`, single symbol),
trim + length-check. It deliberately does NOT call `totp::parse_uri` — the UI
layer does, so non-TOTP QR content fails closed at the same gate as typed URIs.

## 7. Cross-cutting concerns

- **Concurrency:** one UI thread + short KDF/QR background threads per action.
  Vault `Session` is serialized through the UI flow + stale-session checks.
- **Errors:** user-facing via inline label (login) or error window (main);
  crypto errors intentionally vague (`Authentication`).
- **No network:** `Cargo.toml` = `eframe` (glow) + `arboard` + `fs2` + `dirs` +
  `image` + `rqrr` + crypto (`argon2`, `chacha20poly1305`, `hmac`, `sha1/2`) +
  `sys-locale` only. Adding any dialing dependency violates the threat model.
- **Testing:** `cargo test --locked` — RFC vectors, countdown, URI
  accept/reject, validation edges; vault round-trip, no-plaintext-on-disk,
  wrong-pw, O_EXCL, tamper/truncate, nonce-freshness, rotation, stale-write,
  limits, password policy, Go interop fixture; QR round-trip + reject paths;
  i18n key/format/fallback/plural coverage; app filter/dup unit tests.
- **Build/release:** native builds per OS; `.github/workflows/build.yml`
  matrix tests/clippy/fmt/audit + release builds all three OS, then on
  `master`/`v*` packages via `scripts/package_release.py` (magic-check
  `MZ`/`ELF`/`Mach-O`, zip/tar.gz + docs, `SHA256SUMS`) and publishes a GitHub
  Release whose tag must equal `VERSION`.
