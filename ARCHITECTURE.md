# ARCHITECTURE.md

## 1. What this is

TOTP Vault is an **offline desktop authenticator** (Windows + Linux, amd64).
One encrypted file (`vault.dat`) holds all TOTP accounts. One Go binary does
everything: file handling, crypto, code generation, GUI.

Design goals: small surface, fail closed, no network, no recovery backdoor.
Non-goals: camera capture, bulk export/import, sync, browser integration, mobile.
Single-account URI import/export and single QR screenshots pasted from the clipboard are implemented.

```
┌─────────────┐   --vault path    ┌──────────────┐
│ cmd/totpvault│ ────────────────▶ │ internal/ui  │  Fyne controller
│ main.go      │  flock .lock file │ controller   │ ─┐
└─────────────┘  0700 dir         └──────────────┘  │
        │                                           │ uses
        │ default path                              ▼
        │                              ┌────────────────────┐
        │  Win: %APPDATA%\TotpVault\    │ internal/vault     │  Argon2id +
        │  Lin: ~/.local/share/        │ Session            │  XChaCha20-Poly1305
        │       TotpVault/vault.dat    └────────────────────┘
        │                                           │ encrypts []Account
        │                                           ▼
        │                              ┌────────────────────┐
        └─────────────────────────────▶│ internal/totp      │  RFC 6238 pure
                                       │ Account/Code/URI   │  no I/O
                                       └────────────────────┘
```

## 2. Entry point — `cmd/totpvault/main.go` (57 lines)

1. Parses `--vault`; if empty resolves OS default
   (Windows: `os.UserConfigDir()`; Linux: `$XDG_DATA_HOME` or `~/.local/share`,
   both + `TotpVault/vault.dat`).
2. `filepath.Abs` + `os.MkdirAll(dir, 0700)`.
3. `flock.New(abs + ".lock").TryLock()` — second instance shows
   "already open in another instance" via `ui.ShowError` and exits.
4. Calls `ui.Run(abs)`. `defer lock.Close()`.

No crypto, no TOTP logic here. Only path + single-instance guard.

## 3. TOTP core — `internal/totp/totp.go` (210 lines, pure)

`Account{name, issuer, secret, digits, period, algorithm}` — JSON-serializable,
also the vault payload unit.

- `Normalize(a)` — canonicalizes (trim, uppercase secret/algorithm, strip
  whitespace + `=` padding, defaults `SHA1/6/30`) then validates:
  name required ≤256 B, issuer ≤256 B, digits ∈ {6,8}, period 1–300,
  algorithm ∈ {SHA1,SHA256,SHA512}, secret ≤1024 chars and valid Base32
  decoding to ≥10 bytes. Returns error otherwise.
- `Code(a, now)` — re-normalizes, rejects pre-epoch clocks, HMAC-SHA*
  over 8-byte big-endian `floor(unix/period)`, dynamic truncation,
  `mod 10^digits`, zero-padded. Returns `(code, secondsRemaining, err)`.
- `ProvisioningURI(account)` — validates and formats one account as an
  `otpauth://totp/...` URI, preserving encoded label characters and TOTP settings.
- `ParseURI(raw)` — accepts **only** `otpauth://totp/...` (≤8192 chars, no
  userinfo/fragment). Rejects duplicate params and any query key outside
  `{secret, issuer, algorithm, digits, period}` — so `HOTP`, `lock`, `image`,
  etc. fail. Handles `label = [issuer:]name`, checks issuer/label match,
  then delegates to `Normalize` for final validation.

No filesystem, no clock source beyond the passed `time.Time`, no randomness.

## 4. Vault — `internal/vault/vault.go` (286 lines)

### 4.1 Format v1 (fixed, see `SECURITY.md`)

| Offset | Size | Content |
|---|---|---|
| 0–7 | 8 | magic `TOTPVLT` + version `0x01` |
| 8–23 | 16 | Argon2id salt (`crypto/rand` at create / password change) |
| 24–47 | 24 | XChaCha20-Poly1305 nonce (fresh `crypto/rand` **every save**) |
| 48+ | var | `Seal(plaintext JSON {accounts:[...]}, additionalData=header)` = ciphertext + 16 B tag |

KDF pinned: `argon2.IDKey(password, salt, time=3, memory=64MiB, threads=4, keylen=32)`.
KDF params are **not** read from the file — a hostile header cannot tune CPU/RAM.
Header is AEAD additional data, so salt/nonce/magic tampering fails auth.

Limits enforced on read and write: file ≤8 MiB, accounts ≤10 000, every account
re-validated via `totp.Normalize` after decrypt (protects against hand-edited
plaintext produced by a compromised save path).

### 4.2 Session lifecycle

```
Create(path, pw) ── O_EXCL, never overwrites ──▶ Session{key, salt, fingerprint=sha256(file)}
Unlock(path, pw) ── derive → Open → normalize ─▶ Session{key, salt, accounts, fingerprint}
Session.Save(accounts) ── normalize → encrypt(fresh nonce) → replace() ─▶ update accounts+fingerprint
Session.ChangePassword(pw) ── new salt+key → encrypt → replace() ─▶ swap key/salt (old key cleared)
Session.Lock() ── clear(key), zero accounts, nil both
```

- `CheckPassword`: ≥12 runes, ≤1024 bytes.
- `read()`: `LimitReader(maxFileSize+1)`, rejects oversize.
- `replace()`: re-reads file, compares `sha256` to session fingerprint →
  `ErrChanged` on external modification (anti-stale-write / anti-rollback-within-session);
  writes temp `.totpvault-*` in same dir → `Write` → `Sync` → `Close` →
  `Rename` → best-effort dir `Sync` (skipped gracefully on Windows).
  POSIX temp/vault created `0600`; parent dirs `0700`.
- `encrypt()`: `json.Marshal` → `Seal`, `clear(plain)` deferred; rejects `ErrLocked`
  when key is nil and oversize output.
- Errors: `ErrAuthentication` (wrong pw or tamper — deliberately ambiguous),
  `ErrChanged`, `ErrLocked`, plus descriptive format/validation errors.

## 5. UI — `internal/ui/ui.go` (720 lines) + `theme.go` (55 lines)

Single `controller` struct owns everything per window:

```
controller{app, w, path, session *vault.Session, accounts, visible []int,
  selected, list, search, edit/delete/copy/export buttons, status,
  lastActivity+lastWallUnix, idle (default 5m), hideCodes,
  clipboard+clipboardUntil, dialogs+clearOnLock, stopped}
```

### 5.1 Screens

- `Run(path)` — `app.NewWithID`, theme, 720×520 window, close-intercept → `lock()+Quit`,
  starts 500 ms goroutine (`fyne.Do(c.tick)`), `ShowAndRun`, on exit `close(stopped)` +
  `fyne.DoAndWait` final lock (drains a KDF completion queued just before close).
- `login()` — `os.Stat(path)` decides create vs unlock (dir-as-vault and
  unreadable path show Retry/Quit instead of a dead end). Password entries
  (`NewPasswordEntry`), optional confirm + 12-char hint on create. Submit disables
  form, clears entries, shows "Deriving encryption key…", derives in background goroutine
  (Argon2id ~blocks), then `fyne.Do` back to UI thread: error → re-enable + message;
  success → `c.session/c.accounts=touch()+main()`. `stopped` checked so quit-during-KDF
  locks the stray session.
- `main()` — search entry + toolbar (Add / Import URI / Paste QR / Copy / Edit / Delete / Export /
  Settings / About / Lock, inside `HScroll`) + `widget.List`. List rows: left (name bold + issuer), right
  (monospace code or `••• •••` when hide-until-selected, `Ns` countdown bold at ≤5s, progress bar).
  Enter copies the selected code (unless typing in an entry).
  `OnSelected/OnUnselected` → `selectAccount` (enables/disables Copy/Edit/Delete/Export + refresh for masking).
- Dialogs: `accountDialog` (Add/Edit with name/issuer/secret+show-toggle/digits/period/algorithm,
  validates via `Normalize`; edit verifies the index still holds the same account), `importDialog` (password entry for URI, `ParseURI`),
  `exportAccount` (confirmation before copying one account's secret-bearing URI;
  clipboard expires after 15 seconds if unchanged),
  `deleteAccount` (name + issuer + permanent-loss warning; verifies index identity), `settings` (idle 1/2/5/10/15 min + hide-codes checkbox + optional password change),
  `aboutDialog` (vault path, backup reminder, clock note, shortcuts).

### 5.2 Invariants agents must keep

- **All writes via `c.save(accounts)`** → `session.Save` → `c.accounts = session.Accounts()` → `filter()`.
- **Stale-session guard:** every dialog captures `session := c.session` at open and
  aborts on confirm if `c.session != session` (user locked meanwhile); edit/delete
  also verify the index still holds the same account. Untracked-after-dismiss via `untrack()`; `lock()` hides the rest.
- **Secrets cleared:** `secret.SetText("")` / `entry.SetText("")` / `password.SetText("")`
  deferred after each dialog; login clears both password fields before KDF.
  The same closures are registered in `clearOnLock` and run by `lock()`, so
  auto-lock while a dialog is open still wipes entries.
- **`touch()` discipline:** only explicit actions (typing in form/search, select,
  button handlers, show-secret/about) call `touch()` (monotonic + wall). The 500 ms `tick` and mouse movement never do.
- **`tick()` (UI thread via `fyne.Do`):** expire clipboard (clear only if OS clipboard
  still equals copied code or URI) → if `session==nil` return → if `now-lastActivity >= idle`
  **or** wall-clock elapsed `>= idle` (suspend backstop) then `lock()` → else `list.Refresh()`.
- **`lock()`:** run `clearOnLock`, hide all dialogs, `session.Lock(); session=nil`, zero `accounts`,
  reset selection/list handle, `clearClipboard()`, back to `login()`.
- **`filter()`:** unselect, rebuild `visible` by case-insensitive name+issuer substring,
  sort alphabetically (name, then issuer), refresh list, status `"N accounts • path • auto-lock …"`
  or `"showing X of N • …"` while searching.
- **`save()`:** `duplicateError()` rejects same name+issuer or same secret-with-identical-settings
  before `session.Save`; `ErrChanged`/validation surface via `dialog.ShowError`.
- **`pasteQRImage()`:** `touch()` + stale-session capture, `clipboard.Init()`
  (OS image clipboard — Fyne's own clipboard is text-only), status
  "Reading QR image from clipboard…", then background goroutine with 5 s timeout:
  `clipboard.Read(FmtImage)` (always PNG) → `qrimg.DecodeBytes` → `totp.ParseURI` →
  `fyne.Do` back to UI thread (abort if `c.session != session`, else `touch()` +
  `c.save(append(accounts, a))`). Clipboard PNG bytes cleared best-effort after
  decode; empty clipboard / non-image / QR-less / non-TOTP content each produce a
  distinct error dialog and save nothing. See `internal/qrimg/qrimg.go` for limits
  (PNG/JPEG, ≤5 MiB, ≤4000 px/side, ≤16 M px, text ≤8192 chars, single symbol).
- `theme.go`: Windows-only Segoe UI override (respects explicit `FYNE_FONT`), text size 16;
  monospace/symbol styles fall through to Fyne default so codes stay monospace.

## 6. QR clipboard import — `internal/qrimg/qrimg.go`

Pure offline bridge between image bytes and URI text: `DecodeBytes(data)` enforces
size limits, `image.DecodeConfig` header pre-check (dimensions/pixels) before the full
`image.Decode` (PNG/JPEG registered only), then
`qr.Decode(img)` (single symbol; `piglig/go-qr/v2`, zero runtime deps) and trims +
length-checks the payload. It deliberately does NOT call `totp.ParseURI` — the UI
layer does, so non-TOTP QR content (URLs, Wi-Fi, contacts) fails closed at the same
gate as typed URIs. Tests encode a QR from the public RFC secret and round-trip it,
plus reject empty / non-image / QR-less / oversize inputs.

## 7. Cross-cutting concerns

- **Concurrency:** one UI thread (Fyne) + one ticker goroutine + short KDF goroutines
  + short clipboard-read/decode goroutines per paste.
  All widget mutation funneled through `fyne.Do`. Vault `Session` is not safe for
  concurrent `Save`; UI serializes via dialog flow + stale-session check.
- **Errors:** user-facing via inline label (login) or `dialog.ShowError` (main);
  crypto errors intentionally vague (`ErrAuthentication`); startup/lock contention
  via modal `ShowError` window.
- **No network:** `go.mod` = Fyne + `gofrs/flock` + `x/crypto` + `golang.design/x/clipboard`
  (OS image clipboard, Cgo-free) + `piglig/go-qr/v2` (offline QR decode, zero runtime
  deps) only. Adding any dialing dependency violates the threat model.
- **Testing:** `totp_test.go` (18 RFC 6238 vectors, countdown, URI accept/reject, validation edges),
  `vault_test.go` (round-trip, no-plaintext-on-disk, wrong-pw, O_EXCL, tamper/truncate,
  nonce-freshness, rotation, stale-write, limits, password policy), `qrimg_test.go` (QR round-trip from RFC
  secret, non-TOTP QR still decodes but `ParseURI` rejects it, empty/non-image/
  QR-less/oversize rejection), `ui_test.go` (Fyne test driver:
  filter, copy, clipboard-expiry, auto-lock). See `docs/VALIDATION.md`.
- **Build/release:** native CGO builds per OS (see `AGENTS.md`); `.github/workflows/build.yml`
  matrix tests/vets/govulnchecks/builds both OS, then on `master`/`v*` packages via
  `scripts/package_release.py` (magic-check `MZ`/`ELF`, zip/tar.gz + docs, `SHA256SUMS`)
  and publishes a GitHub Release whose tag must equal `VERSION`.
