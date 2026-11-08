package main

// Generates interop/go-vault.dat with the real Go vault code so the
// Rust port proves byte-compatibility (same KDF/AEAD/limits).
// ARCHIVED: Go 1.x implementation lives in archived/go/. Run from the
// archived/go module: `go run ./interop-gen` (paths below assume repo root).

import (
	"fmt"
	"os"

	"github.com/spapas/totpvault/internal/totp"
	"github.com/spapas/totpvault/internal/vault"
)

func main() {
	path := "interop/go-vault.dat"
	_ = os.Remove(path)
	s, err := vault.Create(path, "interop-test-password-012")
	if err != nil {
		panic(err)
	}
	err = s.Save([]totp.Account{
		{Name: "alice@example.com", Issuer: "GitHub", Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Digits: 6, Period: 30, Algorithm: "SHA1"},
		{Name: "bob", Issuer: "Example", Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Digits: 8, Period: 60, Algorithm: "SHA256"},
	})
	if err != nil {
		panic(err)
	}
	s.Lock()
	// Verify the Go side reads it back.
	r, err := vault.Unlock(path, "interop-test-password-012")
	if err != nil {
		panic(err)
	}
	fmt.Println("go fixture ok:", len(r.Accounts()), "accounts")
	r.Lock()

	// Reverse direction: read the Rust-produced fixture, if present.
	if _, err := os.Stat("interop/rust-vault.dat"); err == nil {
		rr, err := vault.Unlock("interop/rust-vault.dat", "interop-test-password-012")
		if err != nil {
			panic("go cannot read rust fixture: " + err.Error())
		}
		fmt.Println("go read rust fixture ok:", len(rr.Accounts()), "accounts")
		for _, a := range rr.Accounts() {
			fmt.Println("  -", a.Issuer, a.Name, a.Digits, a.Period, a.Algorithm)
		}
		rr.Lock()
	}
}
