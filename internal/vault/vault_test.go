package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spapas/totpvault/internal/totp"
)

const testPassword = "a sufficiently long test password"

func TestVaultLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.dat")
	s, err := Create(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Lock()
	a := totp.Account{Name: "private account", Issuer: "private issuer", Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Digits: 6, Period: 30, Algorithm: "SHA1"}
	if err = s.Save([]totp.Account{a}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	for _, secret := range []string{testPassword, a.Name, a.Issuer, a.Secret} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatal("plaintext leaked")
		}
	}
	if _, err = Create(path, testPassword); !errors.Is(err, os.ErrExist) {
		t.Fatalf("create overwrote existing: %v", err)
	}
	if _, err = Unlock(path, "wrong password"); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong password: %v", err)
	}
	s.Lock()
	if err = s.Save(nil); !errors.Is(err, ErrLocked) {
		t.Fatalf("save while locked: %v", err)
	}
	s, err = Unlock(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Lock()
	if got := s.Accounts(); len(got) != 1 || got[0] != a {
		t.Fatalf("lost account: %+v", got)
	}
	copyAccounts := s.Accounts()
	copyAccounts[0].Name = "changed"
	if s.Accounts()[0].Name != a.Name {
		t.Fatal("Accounts exposes mutable state")
	}
	if err = s.ChangePassword("new sufficiently long password"); err != nil {
		t.Fatal(err)
	}
	if _, err = Unlock(path, testPassword); !errors.Is(err, ErrAuthentication) {
		t.Fatal("old password still works")
	}
	next, err := Unlock(path, "new sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	defer next.Lock()
	if len(next.Accounts()) != 1 {
		t.Fatal("password rotation lost accounts")
	}
	if err = next.Save(nil); err != nil {
		t.Fatal(err)
	}
	if err = s.Save([]totp.Account{a}); !errors.Is(err, ErrChanged) {
		t.Fatalf("stale session overwrote disk: %v", err)
	}
}

func TestTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.dat")
	s, err := Create(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	s.Lock()
	original, _ := os.ReadFile(path)
	for _, offset := range []int{8, 24, 48, len(original) - 1} {
		b := append([]byte(nil), original...)
		b[offset] ^= 1
		if err = os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		if got, err := Unlock(path, testPassword); err == nil {
			got.Lock()
			t.Fatalf("tampering at %d authenticated", offset)
		}
	}
	for _, size := range []int{0, 7, 47, 48, 63} {
		if err = os.WriteFile(path, original[:size], 0600); err != nil {
			t.Fatal(err)
		}
		if got, err := Unlock(path, testPassword); err == nil {
			got.Lock()
			t.Fatalf("accepted truncated %d", size)
		}
	}
}

func TestNonceAndFailedSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.dat")
	s, err := Create(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Lock()
	before, _ := os.ReadFile(path)
	if err = s.Save(nil); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if bytes.Equal(before[24:48], after[24:48]) {
		t.Fatal("nonce reused")
	}
	if err = s.Save([]totp.Account{{Name: "bad", Secret: "not base32"}}); err == nil {
		t.Fatal("invalid account saved")
	}
	still, _ := os.ReadFile(path)
	if !bytes.Equal(after, still) {
		t.Fatal("failed save changed disk")
	}
}
