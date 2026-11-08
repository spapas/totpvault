#![windows_subsystem = "windows"]

use std::fs::File;
use std::path::PathBuf;

mod app;
mod prefs;

fn default_vault_path() -> PathBuf {
    if let Some(mut base) = dirs::data_dir() {
        base.push("TotpVault");
        base.push("vault.dat");
        return base;
    }
    PathBuf::from("vault.dat")
}

#[cfg(windows)]
#[link(name = "user32")]
unsafe extern "system" {
    fn MessageBoxW(
        hWnd: *mut core::ffi::c_void,
        text: *const u16,
        caption: *const u16,
        uType: u32,
    ) -> i32;
}

/// Fatal startup error: console (if any) plus a GUI dialog, since the app
/// is windows-subsystem and double-click launches have no console.
fn show_fatal(msg: &str) -> ! {
    eprintln!("TOTP Vault could not start: {msg}");
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let text: Vec<u16> = std::ffi::OsStr::new(msg).encode_wide().chain([0]).collect();
        let caption: Vec<u16> = std::ffi::OsStr::new("TOTP Vault could not start")
            .encode_wide()
            .chain([0])
            .collect();
        unsafe {
            MessageBoxW(core::ptr::null_mut(), text.as_ptr(), caption.as_ptr(), 0x10);
        }
    }
    std::process::exit(1);
}

fn main() {
    let mut vault_path: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--vault" {
            vault_path = args.next();
        } else if let Some(v) = a.strip_prefix("--vault=") {
            vault_path = Some(v.to_string());
        } else if a == "--help" || a == "-h" {
            println!(
                "TOTP Vault\n\nUsage: totpvault [--vault PATH]\n\nOffline TOTP authenticator. Defaults to the OS data dir (TotpVault/vault.dat)."
            );
            return;
        } else if a == "--version" || a == "-V" {
            println!("totpvault {}", env!("CARGO_PKG_VERSION"));
            return;
        }
    }
    let abs = match vault_path {
        Some(p) => PathBuf::from(p),
        None => default_vault_path(),
    };
    let abs = match abs.canonicalize().or_else(|_| {
        let parent = abs.parent().filter(|p| !p.as_os_str().is_empty());
        match parent {
            Some(par) => {
                std::fs::create_dir_all(par).map(|_| par.join(abs.file_name().unwrap_or_default()))
            }
            None => Ok(abs.clone()),
        }
    }) {
        Ok(p) => p,
        Err(e) => show_fatal(&format!("{}: {e}", abs.display())),
    };
    if let Some(dir) = abs.parent() {
        if !dir.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(dir) {
                show_fatal(&format!("{}: {e}", dir.display()));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
    }
    // Single-instance guard: exclusive lock on vault.dat.lock.
    let lock_path = abs.with_extension("dat.lock");
    let lock_file = File::create(&lock_path).unwrap_or_else(|e| {
        show_fatal(&format!("{}: {e}", lock_path.display()));
    });
    {
        use fs2::FileExt;
        if lock_file.try_lock_exclusive().is_err() {
            show_fatal("this vault is already open in another instance");
        }
    }

    let lang = prefs::load_language().unwrap_or_else(totpvault_i18n::detect);
    let theme = prefs::load_theme()
        .map(|t| app::ThemeMode::from_str(&t))
        .unwrap_or_default();
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([720.0, 520.0])
            .with_min_inner_size([560.0, 420.0]),
        ..Default::default()
    };
    let path_str = abs.to_string_lossy().to_string();
    if let Err(e) = eframe::run_native(
        "TOTP Vault",
        options,
        Box::new(move |cc| Ok(Box::new(app::TotpApp::new(cc, path_str, lang, theme)))),
    ) {
        show_fatal(&e.to_string());
    }
    // lock_file drops here, releasing the instance lock.
}
