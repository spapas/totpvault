package ui

import (
	"errors"
	"fmt"
	"image/color"
	"os"
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
	"github.com/spapas/totpvault/internal/totp"
	"github.com/spapas/totpvault/internal/vault"
)

type controller struct {
	app                fyne.App
	w                  fyne.Window
	path               string
	session            *vault.Session
	accounts           []totp.Account
	visible            []int
	selected           int
	list               *widget.List
	search             *widget.Entry
	edit, delete, copy *widget.Button
	status             *widget.Label
	lastActivity       time.Time
	idle               time.Duration
	clipboard          string
	clipboardUntil     time.Time
	dialogs            []dialog.Dialog
	stopped            chan struct{}
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
		ticker := time.NewTicker(250 * time.Millisecond)
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
	if c.session != nil {
		c.session.Lock()
	}
}

func (c *controller) touch()                { c.lastActivity = time.Now() }
func (c *controller) track(d dialog.Dialog) { c.dialogs = append(c.dialogs, d); d.Show() }

func (c *controller) login() {
	_, err := os.Stat(c.path)
	create := os.IsNotExist(err)
	if err != nil && !create {
		c.w.SetContent(container.NewVBox(widget.NewLabel("Cannot read vault"), widget.NewLabel(err.Error())))
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
	if now.Sub(c.lastActivity) >= c.idle {
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
	c.copy = widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), c.copyCode)
	c.edit = widget.NewButtonWithIcon("Edit", theme.DocumentCreateIcon(), func() { c.touch(); c.accountDialog(c.selected) })
	c.delete = widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), c.deleteAccount)
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
		right.Objects[1].(*widget.Label).SetText(fmt.Sprintf("%ds", remaining))
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
	lock := widget.NewButtonWithIcon("Lock", theme.LoginIcon(), c.lock)
	settings := widget.NewButtonWithIcon("Settings", theme.SettingsIcon(), c.settings)
	toolbar := container.NewHBox(add, importURI, c.copy, c.edit, c.delete, settings, lock)
	c.w.SetContent(container.NewBorder(container.NewVBox(widget.NewLabelWithStyle("TOTP Vault", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), c.search, toolbar), c.status, nil, nil, c.list))
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
	c.list.Refresh()
	c.status.SetText(fmt.Sprintf("%d accounts • auto-lock after %s idle", len(c.accounts), c.idle))
}

func (c *controller) selectAccount(index int) {
	c.selected = index
	for _, b := range []*widget.Button{c.copy, c.edit, c.delete} {
		if b == nil {
			continue
		}
		if index < 0 {
			b.Disable()
		} else {
			b.Enable()
		}
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
	c.status.SetText("Code copied • clipboard clears in 15 seconds")
}

func (c *controller) save(accounts []totp.Account) bool {
	if c.session == nil {
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
	if index >= 0 && index < len(c.accounts) {
		a := c.accounts[index]
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
	var d *dialog.FormDialog
	d = dialog.NewForm(title, "Save", "Cancel", []*widget.FormItem{widget.NewFormItem("Account", name), widget.NewFormItem("Issuer", issuer), widget.NewFormItem("Base32 secret", secret), widget.NewFormItem("Digits", digits), widget.NewFormItem("Period (seconds)", period), widget.NewFormItem("Algorithm", algorithm)}, func(ok bool) {
		defer secret.SetText("")
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
		if index < 0 {
			accounts = append(accounts, a)
		} else {
			accounts[index] = a
		}
		c.save(accounts)
	}, c.w)
	d.Resize(fyne.NewSize(500, 360))
	c.track(d)
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
	c.track(d)
}

func (c *controller) deleteAccount() {
	c.touch()
	if c.session == nil || c.selected < 0 {
		return
	}
	session, index := c.session, c.selected
	d := dialog.NewConfirm("Delete account", "Delete "+c.accounts[index].Name+"? Make sure you have another copy of its TOTP key.", func(ok bool) {
		if !ok || c.session != session {
			return
		}
		c.touch()
		accounts := c.session.Accounts()
		accounts = append(accounts[:index], accounts[index+1:]...)
		c.save(accounts)
	}, c.w)
	c.track(d)
}

func (c *controller) settings() {
	c.touch()
	if c.session == nil {
		return
	}
	session := c.session
	minutes := widget.NewSelect([]string{"1", "2", "5", "10", "15"}, func(string) { c.touch() })
	minutes.SetSelected(strconv.Itoa(int(c.idle / time.Minute)))
	password, confirm := widget.NewPasswordEntry(), widget.NewPasswordEntry()
	password.OnChanged = func(string) { c.touch() }
	confirm.OnChanged = func(string) { c.touch() }
	d := dialog.NewForm("Settings", "Save", "Cancel", []*widget.FormItem{widget.NewFormItem("Auto-lock idle minutes", minutes), widget.NewFormItem("New master password (optional)", password), widget.NewFormItem("Repeat new password", confirm)}, func(ok bool) {
		defer password.SetText("")
		defer confirm.SetText("")
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
		n, _ := strconv.Atoi(minutes.Selected)
		c.idle = time.Duration(n) * time.Minute
		c.filter()
	}, c.w)
	d.Resize(fyne.NewSize(600, 260))
	c.track(d)
}
