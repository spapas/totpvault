package ui

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"github.com/spapas/totpvault/internal/totp"
	"github.com/spapas/totpvault/internal/vault"
)

// Fyne's test Window returns a fresh clipboard on every call, unlike desktop windows.
type clipboardWindow struct {
	fyne.Window
	clipboard fyne.Clipboard
}

func (w *clipboardWindow) Clipboard() fyne.Clipboard { return w.clipboard }

func TestFilteringClipboardAndLock(t *testing.T) {
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
		{Name: "bob@example.com", Issuer: "Cloudflare", Secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Digits: 8, Period: 60, Algorithm: "SHA256"},
	}
	if err = s.Save(accounts); err != nil {
		t.Fatal(err)
	}
	w := &clipboardWindow{Window: a.NewWindow("TOTP Vault"), clipboard: test.NewClipboard()}
	c := &controller{app: a, w: w, path: path, session: s, accounts: s.Accounts(), idle: 5 * time.Minute, lastActivity: time.Now()}
	c.w.Resize(fyne.NewSize(720, 520))
	c.main()
	c.w.Show()
	// Captures only public RFC test secrets, never user data.
	if path := os.Getenv("TOTPVault_TEST_SCREENSHOT"); path != "" {
		f, e := os.Create(path)
		if e != nil {
			t.Fatal(e)
		}
		e = png.Encode(f, c.w.Canvas().Capture())
		_ = f.Close()
		if e != nil {
			t.Fatal(e)
		}
	}
	c.search.SetText("cloudflare")
	if len(c.visible) != 1 || c.visible[0] != 1 {
		t.Fatalf("wrong filter: %v", c.visible)
	}
	c.list.Select(0)
	if c.selected != 1 {
		t.Fatal("selection does not map to filtered account")
	}
	c.copyCode()
	if len(c.w.Clipboard().Content()) != 8 {
		t.Fatal("copy did not use selected account")
	}
	c.w.Clipboard().SetContent("unrelated text")
	c.clearClipboard()
	if c.w.Clipboard().Content() != "unrelated text" {
		t.Fatal("cleared user's newer clipboard content")
	}
	c.copyCode()
	c.clipboardUntil = time.Now().Add(-time.Second)
	c.tick()
	if c.w.Clipboard().Content() != "" {
		t.Fatal("clipboard timeout failed")
	}
	c.lastActivity = time.Now().Add(-6 * time.Minute)
	c.tick()
	if c.session != nil || len(c.accounts) != 0 || c.list != nil {
		t.Fatal("auto-lock retained active account state")
	}
	if len(s.Accounts()) != 0 {
		t.Fatal("auto-lock retained vault session")
	}
}
