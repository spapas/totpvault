package ui

import (
	"context"
	"errors"
	"fmt"
	"image/color"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/spapas/totpvault/internal/qrimg"
	"github.com/spapas/totpvault/internal/totp"
	"github.com/spapas/totpvault/internal/vault"
	"golang.design/x/clipboard"
)

type controller struct {
	app                        fyne.App
	w                          fyne.Window
	path                       string
	session                    *vault.Session
	accounts                   []totp.Account
	visible                    []int
	selected                   int
	list                       *widget.List
	search                     *widget.Entry
	edit, delete, copy, export *widget.Button
	status                     *widget.Label
	lastActivity               time.Time
	lastWallUnix               int64
	idle                       time.Duration
	hideCodes                  bool
	clipboard                  string
	clipboardUntil             time.Time
	dialogs                    []dialog.Dialog
	clearOnLock                []func()
	stopped                    chan struct{}
}

func ShowError(err error) {
	a := app.New()
	a.Settings().SetTheme(newAppTheme())
	w := a.NewWindow("TOTP Vault")
	w.SetContent(container.NewVBox(widget.NewLabelWithStyle("TOTP Vault could not start", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), widget.NewLabel(err.Error()), widget.NewButton("Close", a.Quit)))
	w.ShowAndRun()
}

func Run(path string) {
	a := app.NewWithID("io.github.spapas.totpvault")
	a.Settings().SetTheme(newAppTheme())
	c := &controller{app: a, w: a.NewWindow("TOTP Vault"), path: path, idle: 5 * time.Minute, selected: -1, stopped: make(chan struct{})}
	c.w.Resize(fyne.NewSize(720, 520))
	c.w.SetCloseIntercept(func() { c.lock(); a.Quit() })
	c.login()
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fyne.Do(c.tick)
			case <-c.stopped:
				return
			}
		}
	}()
	c.w.ShowAndRun()
	close(c.stopped)
	// Drain any queued UI work (e.g. a KDF completion queued just before
	// close) before the final lock, so a fresh session can't be assigned
	// after we checked it. Runs on the UI thread, same as all mutations.
	fyne.DoAndWait(func() {
		if c.session != nil {
			c.session.Lock()
			c.session = nil
		}
	})
}

func (c *controller) touch() {
	now := time.Now()
	c.lastActivity = now
	c.lastWallUnix = now.Unix()
}

func (c *controller) track(d dialog.Dialog, clear func()) {
	c.dialogs = append(c.dialogs, d)
	if clear != nil {
		c.clearOnLock = append(c.clearOnLock, clear)
	}
	d.Show()
}

func (c *controller) untrack(d dialog.Dialog) {
	for i, e := range c.dialogs {
		if e == d {
			c.dialogs = append(c.dialogs[:i], c.dialogs[i+1:]...)
			break
		}
	}
	// Drop one cleanup to keep the two slices aligned; the dialog's own
	// deferred SetText("") already ran on normal dismiss.
	if len(c.clearOnLock) > 0 {
		c.clearOnLock = c.clearOnLock[:len(c.clearOnLock)-1]
	}
}

func (c *controller) login() {
	info, err := os.Stat(c.path)
	create := os.IsNotExist(err)
	if err != nil && !create {
		retry := widget.NewButton("Retry", func() { c.login() })
		quit := widget.NewButton("Quit", func() { c.app.Quit() })
		c.w.SetContent(container.NewVBox(widget.NewLabel("Cannot read vault"), widget.NewLabel(err.Error()), container.NewHBox(retry, quit)))
		return
	}
	if err == nil && info.IsDir() {
		retry := widget.NewButton("Retry", func() { c.login() })
		quit := widget.NewButton("Quit", func() { c.app.Quit() })
		c.w.SetContent(container.NewVBox(widget.NewLabel("Cannot read vault"), widget.NewLabel("vault path is a directory"), container.NewHBox(retry, quit)))
		return
	}
	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("Master password")
	confirm := widget.NewPasswordEntry()
	confirm.SetPlaceHolder("Repeat master password")
	message := widget.NewLabel("")
	message.Wrapping = fyne.TextWrapWord
	title := "Unlock vault"
	if create {
		title = "Create your vault"
	}
	var submit *widget.Button
	act := func() {
		if submit.Disabled() {
			return
		}
		p := password.Text
		if create {
			if p != confirm.Text {
				message.SetText("Passwords do not match")
				return
			}
			if e := vault.CheckPassword(p); e != nil {
				message.SetText(e.Error())
				return
			}
		}
		submit.Disable()
		password.Disable()
		confirm.Disable()
		password.SetText("")
		confirm.SetText("")
		message.SetText("Deriving encryption key…")
		go func() {
			var s *vault.Session
			var e error
			if create {
				s, e = vault.Create(c.path, p)
			} else {
				s, e = vault.Unlock(c.path, p)
			}
			p = ""
			select {
			case <-c.stopped:
				if s != nil {
					s.Lock()
				}
				return
			default:
			}
			fyne.Do(func() {
				if e != nil {
					message.SetText(e.Error())
					submit.Enable()
					password.Enable()
					confirm.Enable()
					c.w.Canvas().Focus(password)
					return
				}
				c.session = s
				c.accounts = s.Accounts()
				c.touch()
				c.main()
			})
		}()
	}
	submit = widget.NewButton(title, act)
	submit.Importance = widget.HighImportance
	password.OnSubmitted = func(string) { act() }
	confirm.OnSubmitted = func(string) { act() }
	items := []fyne.CanvasObject{widget.NewIcon(theme.LoginIcon()), widget.NewLabelWithStyle(title, fyne.TextAlignCenter, fyne.TextStyle{Bold: true}), password}
	if create {
		items = append(items, confirm, widget.NewLabel("Use a unique master password of at least 12 characters."), widget.NewLabel("A forgotten password cannot be recovered."))
	}
	items = append(items, submit, message)
	// CenterLayout uses the form's minimum size. Reserve a comfortable width
	// while letting the height adapt to validation messages and font settings.
	formWidth := canvas.NewRectangle(color.Transparent)
	formWidth.SetMinSize(fyne.NewSize(320, 0))
	form := container.NewStack(formWidth, container.NewVBox(items...))
	c.w.SetContent(container.NewBorder(nil, widget.NewLabel("Offline • encrypted vault"), nil, nil, container.NewCenter(form)))
	c.w.Canvas().Focus(password)
}

func (c *controller) lock() {
	for _, clear := range c.clearOnLock {
		clear()
	}
	c.clearOnLock = nil
	for _, d := range c.dialogs {
		d.Hide()
	}
	c.dialogs = nil
	if c.session != nil {
		c.session.Lock()
		c.session = nil
	}
	for i := range c.accounts {
		c.accounts[i] = totp.Account{}
	}
	c.accounts = nil
	c.visible = nil
	c.selected = -1
	c.clearClipboard()
	c.list = nil
	c.login()
}

func (c *controller) clearClipboard() {
	if c.clipboard != "" && c.w.Clipboard().Content() == c.clipboard {
		c.w.Clipboard().SetContent("")
	}
	c.clipboard = ""
}

func (c *controller) tick() {
	now := time.Now()
	if c.clipboard != "" && !now.Before(c.clipboardUntil) {
		c.clearClipboard()
	}
	if c.session == nil {
		return
	}
	// Monotonic clock pauses during suspend, so also check wall time to
	// lock after sleep/hibernate even if monotonic elapsed stays small.
	wallElapsed := now.Unix() - c.lastWallUnix
	if now.Sub(c.lastActivity) >= c.idle || (c.lastWallUnix != 0 && wallElapsed >= int64(c.idle/time.Second)) {
		c.lock()
		return
	}
	if c.list != nil {
		c.list.Refresh()
	}
}

func (c *controller) main() {
	c.selected = -1
	c.search = widget.NewEntry()
	c.search.SetPlaceHolder("Search accounts")
	c.search.OnChanged = func(string) { c.touch(); c.filter() }
	c.status = widget.NewLabel("")
	c.status.Wrapping = fyne.TextWrapBreak
	c.copy = widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), c.copyCode)
	c.edit = widget.NewButtonWithIcon("Edit", theme.DocumentCreateIcon(), func() { c.touch(); c.accountDialog(c.selected) })
	c.delete = widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), c.deleteAccount)
	c.export = widget.NewButton("Export", c.exportAccount)
	c.selectAccount(-1)
	c.list = widget.NewList(func() int { return len(c.visible) }, func() fyne.CanvasObject {
		code := widget.NewLabelWithStyle("000 000", fyne.TextAlignTrailing, fyne.TextStyle{Monospace: true, Bold: true})
		count := widget.NewLabel("30s")
		bar := widget.NewProgressBar()
		bar.Min = 0
		bar.Max = 1
		bar.TextFormatter = func() string { return "" }
		return container.NewBorder(nil, nil, nil, container.NewVBox(code, count, bar), container.NewVBox(widget.NewLabelWithStyle("Account", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), widget.NewLabel("Issuer")))
	}, func(id widget.ListItemID, obj fyne.CanvasObject) {
		if id < 0 || id >= len(c.visible) {
			return
		}
		a := c.accounts[c.visible[id]]
		row := obj.(*fyne.Container)
		left := row.Objects[0].(*fyne.Container)
		right := row.Objects[1].(*fyne.Container)
		left.Objects[0].(*widget.Label).SetText(a.Name)
		left.Objects[1].(*widget.Label).SetText(a.Issuer)
		if c.hideCodes && c.visible[id] != c.selected {
			nowUnix := time.Now().Unix()
			rem := a.Period - int(nowUnix%int64(a.Period))
			right.Objects[0].(*widget.Label).SetText("••• •••")
			countLabel := right.Objects[1].(*widget.Label)
			countLabel.TextStyle = fyne.TextStyle{Bold: rem <= 5}
			countLabel.SetText(fmt.Sprintf("%ds", rem))
			right.Objects[2].(*widget.ProgressBar).SetValue(float64(rem) / float64(a.Period))
			return
		}
		code, remaining, err := totp.Code(a, time.Now())
		if err != nil {
			code = "Error"
		}
		if len(code) == 6 {
			code = code[:3] + " " + code[3:]
		} else if len(code) == 8 {
			code = code[:4] + " " + code[4:]
		}
		right.Objects[0].(*widget.Label).SetText(code)
		countLabel := right.Objects[1].(*widget.Label)
		countLabel.TextStyle = fyne.TextStyle{Bold: err == nil && remaining <= 5}
		countLabel.SetText(fmt.Sprintf("%ds", remaining))
		right.Objects[2].(*widget.ProgressBar).SetValue(float64(remaining) / float64(a.Period))
	})
	c.list.OnSelected = func(id widget.ListItemID) {
		c.touch()
		if id >= 0 && id < len(c.visible) {
			c.selectAccount(c.visible[id])
		}
	}
	c.list.OnUnselected = func(widget.ListItemID) { c.selectAccount(-1) }
	add := widget.NewButtonWithIcon("Add", theme.ContentAddIcon(), func() { c.touch(); c.accountDialog(-1) })
	importURI := widget.NewButton("Import URI", c.importDialog)
	pasteQR := widget.NewButton("Paste QR", c.pasteQRImage)
	lock := widget.NewButtonWithIcon("Lock", theme.LoginIcon(), c.lock)
	settings := widget.NewButtonWithIcon("Settings", theme.SettingsIcon(), c.settings)
	about := widget.NewButton("About", c.aboutDialog)
	toolbar := container.NewHBox(add, importURI, pasteQR, c.copy, c.edit, c.delete, c.export, settings, about, lock)
	toolbarScroll := container.NewHScroll(toolbar)
	c.w.SetContent(container.NewBorder(container.NewVBox(widget.NewLabelWithStyle("TOTP Vault", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), c.search, toolbarScroll), c.status, nil, nil, c.list))
	// Enter copies the selected code (unless typing in a text field).
	c.w.Canvas().SetOnTypedKey(func(e *fyne.KeyEvent) {
		if e.Name != fyne.KeyReturn && e.Name != fyne.KeyEnter {
			return
		}
		if _, ok := c.w.Canvas().Focused().(*widget.Entry); ok {
			return
		}
		c.copyCode()
	})
	c.filter()
}

func (c *controller) filter() {
	if c.list == nil {
		return
	}
	c.list.UnselectAll()
	c.selectAccount(-1)
	c.visible = nil
	q := strings.ToLower(c.search.Text)
	for i, a := range c.accounts {
		if strings.Contains(strings.ToLower(a.Name+" "+a.Issuer), q) {
			c.visible = append(c.visible, i)
		}
	}
	sort.Slice(c.visible, func(i, j int) bool {
		a, b := c.accounts[c.visible[i]], c.accounts[c.visible[j]]
		an, bn := strings.ToLower(a.Name), strings.ToLower(b.Name)
		if an != bn {
			return an < bn
		}
		return strings.ToLower(a.Issuer) < strings.ToLower(b.Issuer)
	})
	c.list.Refresh()
	if strings.TrimSpace(q) == "" {
		c.status.SetText(fmt.Sprintf("%d accounts • %s • auto-lock after %s idle", len(c.accounts), c.path, c.idle))
	} else {
		c.status.SetText(fmt.Sprintf("showing %d of %d • %s • auto-lock after %s idle", len(c.visible), len(c.accounts), c.path, c.idle))
	}
}

// duplicateError rejects a save where two different accounts share the same
// identity (name+issuer, case-insensitive) or the same secret. Both cases are
// almost always an accidental double add/import that later shows the wrong code.
func duplicateError(accounts []totp.Account) error {
	seenID := make(map[string]int, len(accounts))
	seenSecret := make(map[string]int, len(accounts))
	for i, a := range accounts {
		id := strings.ToLower(strings.TrimSpace(a.Name)) + "\x00" + strings.ToLower(strings.TrimSpace(a.Issuer))
		if j, ok := seenID[id]; ok {
			return fmt.Errorf("duplicate account %q (entries %d and %d share name and issuer)", a.Name, j+1, i+1)
		}
		seenID[id] = i
		// Same key with identical parameters yields identical codes, so it is
		// almost always a double add/import. Same key with different
		// digits/period/algorithm is allowed (e.g. migration entries).
		secretID := a.Secret + "\x00" + strconv.Itoa(a.Digits) + "\x00" + strconv.Itoa(a.Period) + "\x00" + a.Algorithm
		if j, ok := seenSecret[secretID]; ok {
			return fmt.Errorf("duplicate secret (entries %d and %d hold the same key with identical settings)", j+1, i+1)
		}
		seenSecret[secretID] = i
	}
	return nil
}

func (c *controller) selectAccount(index int) {
	c.selected = index
	for _, b := range []*widget.Button{c.copy, c.edit, c.delete, c.export} {
		if b == nil {
			continue
		}
		if index < 0 {
			b.Disable()
		} else {
			b.Enable()
		}
	}
	// Re-render so hide-until-selected masking follows the selection.
	if c.list != nil {
		c.list.Refresh()
	}
}

func (c *controller) copyCode() {
	c.touch()
	if c.session == nil || c.selected < 0 || c.selected >= len(c.accounts) {
		return
	}
	code, _, err := totp.Code(c.accounts[c.selected], time.Now())
	if err != nil {
		dialog.ShowError(err, c.w)
		return
	}
	c.w.Clipboard().SetContent(code)
	c.clipboard = code
	c.clipboardUntil = time.Now().Add(15 * time.Second)
	c.status.SetText("Copied to clipboard • clears in 15 seconds")
}

func (c *controller) exportAccount() {
	c.touch()
	if c.session == nil || c.selected < 0 || c.selected >= len(c.accounts) {
		return
	}
	session, index := c.session, c.selected
	uri, err := totp.ProvisioningURI(c.accounts[index])
	if err != nil {
		dialog.ShowError(err, c.w)
		return
	}
	d := dialog.NewConfirm("Export TOTP account", "The provisioning URI contains this account’s secret key. Copy it to the clipboard for import in another app? The clipboard will be cleared after 15 seconds if unchanged.", func(ok bool) {
		defer func() { uri = "" }()
		defer c.untrack(d)
		if !ok || c.session != session {
			return
		}
		c.touch()
		c.w.Clipboard().SetContent(uri)
		c.clipboard = uri
		c.clipboardUntil = time.Now().Add(15 * time.Second)
		c.status.SetText("Provisioning URI copied • clipboard clears in 15 seconds")
	}, c.w)
	c.track(d, func() { uri = "" })
}

func (c *controller) save(accounts []totp.Account) bool {
	if c.session == nil {
		return false
	}
	if err := duplicateError(accounts); err != nil {
		dialog.ShowError(err, c.w)
		return false
	}
	if err := c.session.Save(accounts); err != nil {
		dialog.ShowError(err, c.w)
		return false
	}
	c.accounts = c.session.Accounts()
	c.filter()
	return true
}

func (c *controller) accountDialog(index int) {
	if c.session == nil {
		return
	}
	session := c.session
	name, issuer, secret := widget.NewEntry(), widget.NewEntry(), widget.NewPasswordEntry()
	period := widget.NewEntry()
	period.SetText("30")
	digits := widget.NewSelect([]string{"6", "8"}, nil)
	digits.SetSelected("6")
	algorithm := widget.NewSelect([]string{"SHA1", "SHA256", "SHA512"}, nil)
	algorithm.SetSelected("SHA1")
	title := "Add account"
	var orig totp.Account
	isEdit := false
	if index >= 0 && index < len(c.accounts) {
		a := c.accounts[index]
		orig = a
		isEdit = true
		title = "Edit account"
		name.SetText(a.Name)
		issuer.SetText(a.Issuer)
		secret.SetText(a.Secret)
		period.SetText(strconv.Itoa(a.Period))
		digits.SetSelected(strconv.Itoa(a.Digits))
		algorithm.SetSelected(a.Algorithm)
	}
	for _, e := range []*widget.Entry{name, issuer, secret, period} {
		e.OnChanged = func(string) { c.touch() }
	}
	digits.OnChanged = func(string) { c.touch() }
	algorithm.OnChanged = func(string) { c.touch() }
	show := widget.NewCheck("Show secret", func(on bool) { c.touch(); secret.Password = !on; secret.Refresh() })
	var d *dialog.FormDialog
	d = dialog.NewForm(title, "Save", "Cancel", []*widget.FormItem{widget.NewFormItem("Account", name), widget.NewFormItem("Issuer", issuer), widget.NewFormItem("Base32 secret", secret), widget.NewFormItem("", show), widget.NewFormItem("Digits", digits), widget.NewFormItem("Period (seconds)", period), widget.NewFormItem("Algorithm", algorithm)}, func(ok bool) {
		defer secret.SetText("")
		defer c.untrack(d)
		if !ok || c.session != session {
			return
		}
		c.touch()
		p, e := strconv.Atoi(period.Text)
		if e != nil || p < 1 {
			dialog.ShowError(errors.New("invalid period"), c.w)
			return
		}
		n, _ := strconv.Atoi(digits.Selected)
		a, e := totp.Normalize(totp.Account{Name: name.Text, Issuer: issuer.Text, Secret: secret.Text, Period: p, Digits: n, Algorithm: algorithm.Selected})
		if e != nil {
			dialog.ShowError(e, c.w)
			return
		}
		accounts := c.session.Accounts()
		if !isEdit {
			accounts = append(accounts, a)
		} else {
			if index < 0 || index >= len(accounts) || accounts[index] != orig {
				dialog.ShowError(errors.New("account changed meanwhile; reopen and try again"), c.w)
				return
			}
			accounts[index] = a
		}
		c.save(accounts)
	}, c.w)
	d.Resize(fyne.NewSize(500, 360))
	c.track(d, func() { secret.SetText("") })
}

func (c *controller) importDialog() {
	c.touch()
	if c.session == nil {
		return
	}
	session := c.session
	entry := widget.NewPasswordEntry()
	entry.SetPlaceHolder("otpauth://totp/…")
	entry.OnChanged = func(string) { c.touch() }
	d := dialog.NewForm("Import TOTP URI", "Import", "Cancel", []*widget.FormItem{widget.NewFormItem("URI", entry)}, func(ok bool) {
		defer entry.SetText("")
		defer c.untrack(d)
		if !ok || c.session != session {
			return
		}
		c.touch()
		a, err := totp.ParseURI(entry.Text)
		if err != nil {
			dialog.ShowError(err, c.w)
			return
		}
		c.save(append(c.session.Accounts(), a))
	}, c.w)
	d.Resize(fyne.NewSize(560, 180))
	c.track(d, func() { entry.SetText("") })
}

// pasteQRImage reads a QR screenshot from the OS clipboard (image, not text),
// decodes it offline and imports the enclosed otpauth URI. Fyne's own
// clipboard is text-only, so this uses the OS image clipboard directly.
func (c *controller) pasteQRImage() {
	c.touch()
	if c.session == nil {
		return
	}
	session := c.session
	if err := clipboard.Init(); err != nil {
		dialog.ShowError(fmt.Errorf("clipboard unavailable: %w", err), c.w)
		return
	}
	c.status.SetText("Reading QR image from clipboard…")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		data, err := clipboard.Read(ctx, clipboard.FmtImage)
		if err != nil {
			fyne.Do(func() {
				if c.session != session {
					return
				}
				dialog.ShowError(errors.New("no image in clipboard — copy a QR screenshot first (Win+Shift+S)"), c.w)
			})
			return
		}
		text, err := qrimg.DecodeBytes(data)
		clear(data)
		if err != nil {
			fyne.Do(func() {
				if c.session != session {
					return
				}
				dialog.ShowError(err, c.w)
			})
			return
		}
		a, err := totp.ParseURI(text)
		text = ""
		if err != nil {
			fyne.Do(func() {
				if c.session != session {
					return
				}
				dialog.ShowError(fmt.Errorf("QR code is not a valid TOTP URI: %w", err), c.w)
			})
			return
		}
		fyne.Do(func() {
			if c.session != session {
				return
			}
			c.touch()
			c.save(append(c.session.Accounts(), a))
		})
	}()
}

func (c *controller) deleteAccount() {
	c.touch()
	if c.session == nil || c.selected < 0 {
		return
	}
	session, index := c.session, c.selected
	if index < 0 || index >= len(c.accounts) {
		return
	}
	orig := c.accounts[index]
	name := orig.Name
	if orig.Issuer != "" {
		name += " (" + orig.Issuer + ")"
	}
	d := dialog.NewConfirm("Delete account", "Delete "+name+"? Its secret is removed permanently and codes stop working. Make sure you have a backup or another copy of its TOTP key.", func(ok bool) {
		defer c.untrack(d)
		if !ok || c.session != session {
			return
		}
		c.touch()
		accounts := c.session.Accounts()
		if index < 0 || index >= len(accounts) || accounts[index] != orig {
			dialog.ShowError(errors.New("account changed meanwhile; reopen and try again"), c.w)
			return
		}
		accounts = append(accounts[:index], accounts[index+1:]...)
		c.save(accounts)
	}, c.w)
	c.track(d, nil)
}

func (c *controller) settings() {
	c.touch()
	if c.session == nil {
		return
	}
	session := c.session
	minutes := widget.NewSelect([]string{"1", "2", "5", "10", "15"}, func(string) { c.touch() })
	minutes.SetSelected(strconv.Itoa(int(c.idle / time.Minute)))
	hide := widget.NewCheck("Hide codes until selected", func(bool) { c.touch() })
	hide.SetChecked(c.hideCodes)
	password, confirm := widget.NewPasswordEntry(), widget.NewPasswordEntry()
	password.OnChanged = func(string) { c.touch() }
	confirm.OnChanged = func(string) { c.touch() }
	d := dialog.NewForm("Settings", "Save", "Cancel", []*widget.FormItem{widget.NewFormItem("Auto-lock idle minutes", minutes), widget.NewFormItem("Privacy", hide), widget.NewFormItem("New master password (optional)", password), widget.NewFormItem("Repeat new password", confirm)}, func(ok bool) {
		defer password.SetText("")
		defer confirm.SetText("")
		defer c.untrack(d)
		if !ok || c.session != session {
			return
		}
		c.touch()
		if password.Text != "" || confirm.Text != "" {
			if password.Text != confirm.Text {
				dialog.ShowError(errors.New("passwords do not match"), c.w)
				return
			}
			if err := c.session.ChangePassword(password.Text); err != nil {
				dialog.ShowError(err, c.w)
				return
			}
		}
		n, err := strconv.Atoi(minutes.Selected)
		if err != nil || n <= 0 {
			dialog.ShowError(errors.New("invalid idle minutes"), c.w)
			return
		}
		c.idle = time.Duration(n) * time.Minute
		c.hideCodes = hide.Checked
		c.filter()
	}, c.w)
	d.Resize(fyne.NewSize(600, 280))
	c.track(d, func() { password.SetText(""); confirm.SetText("") })
}

func (c *controller) aboutDialog() {
	c.touch()
	msg := "Offline TOTP authenticator.\n\n" +
		"Vault: " + c.path + "\n" +
		"Back up vault.dat to a safe place — a forgotten master password cannot be recovered.\n\n" +
		"If all codes fail, check the system clock.\n\n" +
		"Enter copies the selected code. Hide codes until selected in Settings."
	d := dialog.NewInformation("About TOTP Vault", msg, c.w)
	d.SetOnClosed(func() { c.untrack(d) })
	c.track(d, nil)
}
