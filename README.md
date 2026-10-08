# TOTP Vault

A small offline authenticator for Windows and Linux, written in Go with Fyne.

## Features

- Create and unlock an encrypted vault with a master password.
- Add, edit, delete and search TOTP accounts.
- Import `otpauth://totp/...` provisioning URIs.
- SHA-1, SHA-256 and SHA-512; 6 or 8 digits; configurable period (default 30 seconds).
- Live codes and countdown bars; copy the current code to the clipboard.
- Clear the copied code after 15 seconds, if the clipboard still contains it.
- Manual lock and auto-lock after 5 minutes of inactivity (1–15 minutes per session).
- Change the master password from Settings.
- No server, account registration, telemetry or network requests.

## Run

Download the Windows or Linux artifact from the repository's **Actions → Build and test** page after a successful run. Extract the archive, then start `totpvault.exe` or `./totpvault`. Linux requires an OpenGL-capable desktop and its normal X11/Wayland compatibility libraries. The Windows executable uses the system OpenGL driver; no Go compiler or WebView is required to run it.

On first launch, choose a unique master password with at least 12 characters. A forgotten password cannot be recovered. Click **Add** to enter a Base32 secret, or **Import URI** to paste a provisioning URI. Select an account to copy, edit or delete it.

The default encrypted file is:

| OS | Location |
|---|---|
| Windows | `%APPDATA%\TotpVault\vault.dat` |
| Linux | `$XDG_DATA_HOME/TotpVault/vault.dat`, or `~/.local/share/TotpVault/vault.dat` |

Choose another file with `totpvault --vault /path/to/vault.dat` (Windows: `totpvault.exe --vault C:\path\vault.dat`). Only one process can open a given vault. Close the app before copying or restoring the file.

Back up **vault.dat** to another safe location. It remains encrypted, and the same file works on both platforms. Changing the master password re-encrypts the current vault; older backups still require their original password. Keep the computer clock synchronized for correct codes.

## Build on Windows (Command Prompt)

Install Go 1.26 or later and a 64-bit MinGW-w64 GCC compiler. With Scoop already installed, you can use `scoop install go gcc`; MSYS2 is not required for this route. Ensure `go` and `gcc` are available in CMD:

```bat
git clone --branch master https://github.com/spapas/totpvault.git
cd totpvault
set CGO_ENABLED=1
go mod download
go test ./internal/totp ./internal/vault
go build -trimpath -ldflags="-s -w -H=windowsgui" -o dist\totpvault.exe ./cmd/totpvault
dist\totpvault.exe
```

The first Fyne build can take several minutes. For development, use `go run ./cmd/totpvault`.

## Build on Linux (Ubuntu/Debian)

Install Go 1.26 or later, then:

```sh
sudo apt-get install gcc pkg-config libgl1-mesa-dev xorg-dev libwayland-dev libxkbcommon-dev
git clone --branch master https://github.com/spapas/totpvault.git
cd totpvault
go mod download
go test -race ./...
go build -trimpath -ldflags="-s -w" -o dist/totpvault ./cmd/totpvault
./dist/totpvault
```

Fyne uses C/OpenGL bindings: ordinary `GOOS=windows go build` from Linux is insufficient. Build natively on each OS or provide a matching cross C compiler. GitHub Actions builds both platforms and uploads binaries automatically.

## Layout

| Directory | Purpose |
|---|---|
| `cmd/totpvault` | Entry point, paths, exclusive instance lock |
| `internal/totp` | RFC 6238 generation and provisioning URI parsing |
| `internal/vault` | Password derivation, authenticated encryption, atomic saves |
| `internal/ui` | Fyne desktop UI and session lifecycle |

See [SECURITY.md](SECURITY.md) for the format, threat model and limitations. See [docs/VALIDATION.md](docs/VALIDATION.md) for the checks performed on the initial implementation.

QR image/camera import and authenticator-specific bulk exports are not implemented in this version.
