package ui

import (
	_ "embed"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"github.com/spapas/totpvault/internal/i18n"
	"github.com/spapas/totpvault/internal/totp"
	"github.com/spapas/totpvault/internal/vault"
)

//go:embed ui.go
var uiSource string

// Every message ID referenced by the UI must exist in the source table,
// otherwise users see raw keys like "btn.import_uri". The UI source is
// embedded at compile time so the check works with -trimpath builds too.
func TestAllUIKeysTranslated(t *testing.T) {
	re := regexp.MustCompile(`"((?:app|btn|login|main|status|export|acct|import|qr|delete|settings|about|dup|err)\.[a-z0-9_]+)"`)
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(uiSource, -1) {
		key := string(m[1])
		if seen[key] {
			continue
		}
		seen[key] = true
		if i18n.Get("en", key) == key {
			t.Fatalf("UI key %q missing from English table", key)
		}
	}
	if len(seen) == 0 {
		t.Fatal("no UI keys found; regex broken")
	}
}

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
