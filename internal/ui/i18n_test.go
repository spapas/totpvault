package ui

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"github.com/spapas/totpvault/internal/totp"
	"github.com/spapas/totpvault/internal/vault"
)

// Switching language rebuilds the visible strings without touching the vault.
func TestLanguageSwitch(t *testing.T) {
	a := test.NewApp()
	defer a.Quit()
	a.Settings().SetTheme(newAppTheme())
	path := filepath.Join(t.TempDir(), "vault.dat")
	s, err := vault.Create(path, "a long test master password")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Lock()
	accounts := []totp.Account{
		{Name: "alice@example.com", Issuer: "GitHub", Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Digits: 6, Period: 30, Algorithm: "SHA1"},
	}
	if err = s.Save(accounts); err != nil {
		t.Fatal(err)
	}
	w := &clipboardWindow{Window: a.NewWindow("TOTP Vault"), clipboard: test.NewClipboard()}
	c := &controller{app: a, w: w, path: path, session: s, accounts: s.Accounts(), idle: 5 * time.Minute, lastActivity: time.Now(), lang: "el"}
	c.w.Resize(fyne.NewSize(720, 520))
	c.main()
	c.w.Show()
	if c.search.PlaceHolder != "Αναζήτηση λογαριασμών" {
		t.Fatalf("greek search placeholder: %q", c.search.PlaceHolder)
	}
	if !strings.Contains(c.status.Text, "αυτόματο κλείδωμα") {
		t.Fatalf("greek status: %q", c.status.Text)
	}
	c.lang = "fr"
	c.rebuild()
	if c.search.PlaceHolder != "Rechercher des comptes" {
		t.Fatalf("french search placeholder: %q", c.search.PlaceHolder)
	}
	if len(c.visible) != 1 || c.selected != -1 {
		t.Fatal("rebuild must keep accounts and reset selection")
	}
	// Unknown language falls back to English, never blank.
	c.lang = "xx"
	c.rebuild()
	if c.search.PlaceHolder != "Search accounts" {
		t.Fatalf("fallback placeholder: %q", c.search.PlaceHolder)
	}
}
