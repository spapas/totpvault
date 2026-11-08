# Security design

## Vault format, version 1

All account names, issuers and secrets are encrypted together as a JSON payload. The master password is not written to disk. Version 1 has a fixed binary header:

| Bytes | Contents |
|---|---|
| 0–7 | `TOTPVLT` plus version byte `0x01` |
| 8–23 | Random 16-byte Argon2id salt |
| 24–47 | Fresh random 24-byte XChaCha20-Poly1305 nonce |
| 48 onward | Ciphertext and 16-byte authentication tag |

Argon2id derives a 32-byte encryption key using 64 MiB memory, 3 iterations and 4 lanes. Parameters are fixed by the format version, so a hostile header cannot request arbitrary KDF work. The complete header is AEAD additional authenticated data. Nonces come from the OS RNG on every save. Password changes generate a new salt and key.

Input files are limited to 8 MiB and 10,000 accounts. TOTP settings and Base32 secrets are validated before storage and after decryption. Unsupported formats and provisioning parameters fail rather than guessing. Format v1 is unchanged between the archived Go 1.x app and the Rust 2.x app; both open each other's vaults (see `interop/` fixtures and `vault::tests::go_interop_fixture`).

Writes use a same-directory temporary file containing ciphertext only, sync it, then rename it over the old vault. The directory is synced where supported. New vault creation uses exclusive creation and cannot overwrite an existing file. A process lock prevents two application instances from opening the same path; a file fingerprint rejects stale-session writes. Network filesystems, alternate path aliases and programs that ignore the lock may not provide these guarantees. Use a local vault file. POSIX files are created with mode 0600 and app directories with 0700. Windows relies on the user profile directory's inherited ACLs; macOS relies on the user's Library permissions.

## Locking and memory

The encryption key is held in memory only while unlocked and zeroized on lock (best-effort `zeroize`; Rust's allocator, GUI copies, swap, crash dumps and clipboard history **cannot be guaranteed erased**). Account references and GUI content are discarded. Password input fields are cleared after submission. Auto-lock uses application interactions (typing in forms/search, selection, button clicks) as activity; watching the countdown does not reset it. Settings are per session and revert to a 5-minute timeout on restart. The interface language and theme are the deliberate exceptions: auto-detected (language) / system (theme), switchable in Settings, persisted as non-secret tags in `TotpVault/prefs.json` under the OS config dir.

Locking is application access control and best-effort cleanup; this is not protection against malware, a debugger, keyloggers or a compromised operating system. Exporting an account copies its provisioning URI, including the TOTP secret, to the clipboard only after confirmation. Clipboard clearing after 15 seconds only affects the current clipboard if it still equals the copied code or URI; it cannot revoke previous copies or clear every OS clipboard-history entry.

## QR paste

`Paste QR` reads an image (not text) from the OS clipboard and decodes it fully offline. Guardrails: PNG/JPEG only, ≤5 MiB, dimensions ≤4000 px per side and ≤16 M pixels total, single symbol per paste, decoded text ≤8192 chars, then the existing `parse_uri` validation decides. A QR holding anything but a valid `otpauth://totp/...` URI is rejected; nothing is saved on failure.

Image decoders (PNG/JPEG) and QR detectors enlarge the attack surface versus typed URIs: a malicious screenshot could exploit a decoder bug before validation runs. Pastes are untrusted input — keep dependencies pinned, `cargo audit` clean, and never log image bytes, decoded URIs, or secrets.

## Threat model

The encrypted vault protects stored secrets when an attacker obtains the file without the master password. A weak password still permits offline guessing. A forgotten master password cannot be recovered. Authenticated encryption detects modification but does not prevent deletion, rollback to an old valid file or loss of the file. Keep encrypted backups and recovery codes. Your clock must be correct; this application does not contact time servers.

This rewrite has not undergone an independent security audit. Automated tests validate RFC vectors, encryption round trips, authentication failures, tampering, password rotation, nonce freshness, stale writes and Go/Rust interop; they do not prove the entire application secure.

For vulnerability reports, use a private GitHub security report if enabled. Do not attach real provisioning URIs, secrets, passwords or vault files to public issues.
