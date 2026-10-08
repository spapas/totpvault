package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/gofrs/flock"
	"github.com/spapas/totpvault/internal/ui"
)

func main() {
	path := flag.String("vault", "", "path to encrypted vault")
	flag.Parse()
	if *path == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if runtime.GOOS == "linux" {
			base = os.Getenv("XDG_DATA_HOME")
			if base == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				base = filepath.Join(home, ".local", "share")
			}
		}
		*path = filepath.Join(base, "TotpVault", "vault.dat")
	}
	abs, err := filepath.Abs(*path)
	if err != nil {
		ui.ShowError(err)
		return
	}
	if err = os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
		ui.ShowError(err)
		return
	}
	lock := flock.New(abs + ".lock")
	ok, err := lock.TryLock()
	if err != nil {
		ui.ShowError(err)
		return
	}
	if !ok {
		ui.ShowError(fmt.Errorf("this vault is already open in another instance"))
		return
	}
	defer lock.Close()
	ui.Run(abs)
}
