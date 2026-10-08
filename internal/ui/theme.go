package ui

import (
	"os"
	"path/filepath"
	"runtime"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

type appTheme struct {
	fyne.Theme
	fonts map[fyne.TextStyle]fyne.Resource
}

func newAppTheme() fyne.Theme {
	t := &appTheme{Theme: theme.DefaultTheme()}
	// Use Windows' installed UI font without redistributing Microsoft fonts.
	// Preserve an explicit Fyne font preference and fall back on other systems.
	if runtime.GOOS == "windows" && os.Getenv("FYNE_FONT") == "" {
		windowsDir := os.Getenv("WINDIR")
		if windowsDir == "" {
			windowsDir = `C:\Windows`
		}
		t.fonts = make(map[fyne.TextStyle]fyne.Resource)
		for style, filename := range map[fyne.TextStyle]string{
			{}:                         "segoeui.ttf",
			{Bold: true}:               "segoeuib.ttf",
			{Italic: true}:             "segoeuii.ttf",
			{Bold: true, Italic: true}: "segoeuiz.ttf",
		} {
			if font, err := fyne.LoadResourceFromPath(filepath.Join(windowsDir, "Fonts", filename)); err == nil {
				t.fonts[style] = font
			}
		}
	}
	return t
}

func (t *appTheme) Font(style fyne.TextStyle) fyne.Resource {
	if !style.Monospace && !style.Symbol {
		if font := t.fonts[fyne.TextStyle{Bold: style.Bold, Italic: style.Italic}]; font != nil {
			return font
		}
	}
	return t.Theme.Font(style)
}

func (t *appTheme) Size(name fyne.ThemeSizeName) float32 {
	if name == theme.SizeNameText {
		return 16
	}
	return t.Theme.Size(name)
}
