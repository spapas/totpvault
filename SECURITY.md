# Security design

## Vault format, version 1

All account names, issuers and secrets are encrypted together as a JSON payload. The master password is not written to disk. Version 1 has a fixed binary header:

| Bytes | Contents |
|---|---|
| 0–7 | `TOTPVLT` plus version byte `0x01` |
| 8–23 | Random 16-byte Argon2id salt |
| 24–47 | Fresh random 24-byte XChaCha20-Poly1305 nonce |
| 48 onward | Ciphertext and 16-byte authentication tag |

Argon2id derives a 32-byte encryption key using 64 MiB memory, 3 iterations and 4 lanes. Parameters are fixed by the format version, so a hostile header cannot request arbitrary KDF work. The complete header is AEAD additional authenticated data. Nonces come from `crypto/rand` on every save. Password changes generate a new salt and key.

Input files are limited to 8 MiB and 10,000 accounts. TOTP settings and Base32 secrets are validated before storage and after decryption. Unsupported formats and provisioning parameters fail rather than guessing.

Writes use a same-directory temporary file containing ciphertext only, sync it, then rename it over the old vault. The directory is synced where supported. New vault creation uses exclusive creation and cannot overwrite an existing file. A process lock prevents two application instances from opening the same path; a file fingerprint rejects stale-session writes. Network filesystems, alternate path aliases and programs that ignore the lock may not provide these guarantees. Use a local vault file. POSIX files are created with mode 0600 and app directories with 0700. Windows relies on the user profile directory's inherited ACLs.

## Locking and memory

The encryption key is held in memory only while unlocked and overwritten on lock. Account references and GUI content are discarded. Password input fields are cleared after submission. Auto-lock uses application interactions (typing in forms/search, selection, button clicks) as activity; moving the mouse or watching the countdown does not reset it. Settings are per session and revert to a 5-minute timeout on restart.

Go and the UI/OS use managed memory: string copies, garbage-collected allocations, swap, crash dumps and clipboard history **cannot be guaranteed erased**. Locking is application access control and best-effort cleanup; this is not protection against malware, a debugger, keyloggers or a compromised operating system. Use disk encryption and a trusted computer. Clipboard clearing only affects the current clipboard if it still equals the copied code; it cannot revoke previous copies or clear every OS clipboard-history entry.

## QR paste

`Paste QR` reads an image (not text) from the OS clipboard — Fyne's own clipboard is text-only — and decodes it fully offline with a zero-dependency library. Guardrails: PNG/JPEG only, ≤5 MiB, dimensions ≤4000 px per side and ≤16 M pixels total, single symbol per paste, decoded text ≤8192 chars, then the existing `totp.ParseURI` validation decides. A QR holding anything but a valid `otpauth://totp/...` URI is rejected; nothing is saved on failure. Clipboard bytes are cleared best-effort after decoding; the source image stays in the OS clipboard/history — clear it yourself if the QR photo is sensitive.

Image decoders (PNG/JPEG) and QR detectors enlarge the attack surface versus typed URIs: a malicious screenshot could exploit a decoder bug before validation runs. Pastes are untrusted input — keep dependencies pinned, `govulncheck` clean, and never log image bytes, decoded URIs, or secrets.

## Threat model

The encrypted vault protects stored secrets when an attacker obtains the file without the master password. A weak password still permits offline guessing. A forgotten master password cannot be recovered. Authenticated encryption detects modification but does not prevent deletion, rollback to an old valid file or loss of the file. Keep encrypted backups and recovery codes. Your clock must be correct; this application does not contact time servers.

This is a first implementation and has not undergone an independent security audit. Automated tests validate RFC vectors, encryption round trips, authentication failures, tampering, password rotation, nonce freshness and stale writes; they do not prove the entire application secure.

For vulnerability reports, use a private GitHub security report if enabled. Do not attach real provisioning URIs, secrets, passwords or vault files to public issues.
