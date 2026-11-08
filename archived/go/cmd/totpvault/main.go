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

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	ui.ShowError(err)
	os.Exit(1)
}

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
		fail(err)
	}
	if err = os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
		fail(err)
	}
	if runtime.GOOS != "windows" {
		// MkdirAll is a no-op for pre-existing dirs; tighten one that
		// was created lax (e.g. under /tmp) before we rely on it.
		_ = os.Chmod(filepath.Dir(abs), 0700)
	}
	lock := flock.New(abs + ".lock")
	ok, err := lock.TryLock()
	if err != nil {
		fail(err)
	}
	if !ok {
		fail(fmt.Errorf("this vault is already open in another instance"))
	}
	defer lock.Close()
	ui.Run(abs)
}
