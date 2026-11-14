//! egui controller: login -> main list -> dialogs. Single UI thread; KDF and
//! QR-clipboard work run on background threads and report back via channel.
//!
//! Session discipline mirrors `archived/go/internal/ui`: all writes go through
//! `save()`; dialogs abort when the session was locked meanwhile; edit/delete
//! verify the account index still holds the same account; only explicit
//! actions (typing, selection, buttons) reset the idle timer.

use std::collections::HashSet;
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui;

use totpvault_i18n as i18n;
use totpvault_totp as totp;
use totpvault_vault as vault;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn spaced(code: &str) -> String {
    match code.len() {
        6 => format!("{} {}", &code[..3], &code[3..]),
        8 => format!("{} {}", &code[..4], &code[4..]),
        _ => code.to_string(),
    }
}

/// Offline QR encode for the export dialog: validated `otpauth://` URI bytes
/// -> grayscale modules -> `egui::ColorImage`. Fails closed when the payload
/// does not fit a single QR symbol (some long but valid URIs exceed QR
/// capacity); callers show the error instead of saving anything.
fn qr_color_image(uri: &str) -> Result<egui::ColorImage, String> {
    let code =
        qrcode::QrCode::new(uri.as_bytes()).map_err(|e| format!("could not render QR: {e}"))?;
    // 360px box keeps one dialog readable without DPR-dependent scaling.
    let img = code
        .render::<image::Luma<u8>>()
        .max_dimensions(360, 360)
        .quiet_zone(true)
        .build();
    let (w, h) = (img.width() as usize, img.height() as usize);
    if w == 0 || h == 0 || w > 2000 || h > 2000 {
        return Err("could not render QR".to_string());
    }
    Ok(egui::ColorImage::from_gray(
        [w, h],
        img.into_raw().as_slice(),
    ))
}

/// Password strength 0–4 (offline heuristic, no network): one point each for
/// 12+ chars (runes), mixed case, a digit, a non-alphanumeric. Pure.
pub fn password_strength(pw: &str) -> u8 {
    let runes = pw.chars().count();
    let mut score = 0u8;
    if runes >= 12 {
        score += 1;
    }
    let (mut lower, mut upper, mut digit, mut symbol) = (false, false, false, false);
    for c in pw.chars() {
        if c.is_ascii_lowercase() {
            lower = true;
        } else if c.is_ascii_uppercase() {
            upper = true;
        } else if c.is_ascii_digit() {
            digit = true;
        } else if !c.is_alphanumeric() {
            symbol = true;
        } else {
            // Non-ASCII alphanumeric: counts as a class on its own.
            symbol = true;
        }
    }
    if lower && upper {
        score += 1;
    }
    if digit {
        score += 1;
    }
    if symbol {
        score += 1;
    }
    score.min(4)
}

/// Stable pin key: lowercase trimmed `name\0issuer`. Pure.
pub fn pin_key(name: &str, issuer: &str) -> String {
    format!(
        "{}\x00{}",
        name.trim().to_lowercase(),
        issuer.trim().to_lowercase()
    )
}

/// Pinned accounts first, alphabetical order preserved inside each group.
/// `visible` must already be sorted by [`filter`]. Pure.
pub fn order_pinned(
    accounts: &[totp::Account],
    visible: &[usize],
    pinned: &HashSet<String>,
) -> Vec<usize> {
    let mut pin = Vec::new();
    let mut rest = Vec::new();
    for &i in visible {
        let a = &accounts[i];
        if pinned.contains(&pin_key(&a.name, &a.issuer)) {
            pin.push(i);
        } else {
            rest.push(i);
        }
    }
    pin.extend(rest);
    pin
}

/// Default backup destination: `<vault>.bak`. Pure.
pub fn backup_dest_default(vault_path: &str) -> String {
    format!("{vault_path}.bak")
}

/// True when the wall clock jumped clearly backwards (codes may be wrong).
/// Pure: both inputs are Unix seconds, 0 = unknown clock.
pub fn clock_went_backwards(prev_wall: i64, now_wall: i64) -> bool {
    prev_wall > 0 && now_wall > 0 && now_wall + 60 < prev_wall
}

/// Per-session font scale steps used by Settings. Pure.
pub fn font_scale_from_idx(idx: usize) -> f32 {
    match idx {
        0 => 0.9,
        2 => 1.15,
        3 => 1.3,
        _ => 1.0,
    }
}

pub fn font_idx_from_scale(scale: f32) -> usize {
    if (scale - 0.9).abs() < 0.01 {
        0
    } else if (scale - 1.15).abs() < 0.01 {
        2
    } else if (scale - 1.3).abs() < 0.01 {
        3
    } else {
        1
    }
}

/// True while Caps Lock is engaged. Windows-only via direct user32 import
/// (no new dependency, OS API only); other platforms return false, where the
/// login screen simply omits the warning. Pure query, no I/O.
#[cfg(windows)]
fn caps_lock_on() -> bool {
    #[link(name = "user32")]
    unsafe extern "system" {
        fn GetKeyState(n_virt_key: i32) -> i16;
    }
    const VK_CAPITAL: i32 = 0x14;
    unsafe { GetKeyState(VK_CAPITAL) & 1 == 1 }
}

#[cfg(not(windows))]
fn caps_lock_on() -> bool {
    false
}

/// Code of the *next* period, shown only for the selected account so extra
/// HMAC work stays O(1) per tick. Pure.
pub fn next_code_text(account: &totp::Account, now: i64) -> Option<String> {
    if account.period < 1 || now < 0 {
        return None;
    }
    let cur = now.div_euclid(account.period);
    let t = cur.saturating_add(1).saturating_mul(account.period);
    totp::code(account, t).ok().map(|(c, _)| spaced(&c))
}

/// Copy the encrypted vault file as-is (manual Backup dialog and the
/// best-effort auto-`.bak` share this one path). No crypto here. Pure I/O.
pub fn backup_vault_file(src: &str, dest: &str) -> std::io::Result<u64> {
    std::fs::copy(src, dest)
}

/// 32x32 RGBA padlock for the tray: transparent rounded square, teal base,
/// white shackle + body, dark keyhole. Pure.
pub fn tray_icon_rgba() -> (Vec<u8>, u32, u32) {
    const S: u32 = 32;
    const TEAL: [u8; 4] = [13, 148, 136, 255];
    const WHITE: [u8; 4] = [255, 255, 255, 255];
    const DARK: [u8; 4] = [10, 110, 100, 255];
    let mut px = vec![0u8; (S * S * 4) as usize];
    for y in 0..S {
        for x in 0..S {
            // Rounded-square mask, radius 7 on a 32px box.
            let dx = ((x as i32 - 16).abs() - 9).max(0) as f32;
            let dy = ((y as i32 - 16).abs() - 9).max(0) as f32;
            if dx * dx + dy * dy > 49.0 {
                continue; // transparent corner
            }
            let mut c = TEAL;
            // Shackle ring, center (16,13), r 5.5, upper part only.
            let sx = x as f32 - 16.0;
            let sy = y as f32 - 13.0;
            if ((sx * sx + sy * sy).sqrt() - 5.5).abs() <= 1.4 && y <= 14 {
                c = WHITE;
            }
            // Body x 10..22, y 14..26.
            if (10..22).contains(&x) && (14..26).contains(&y) {
                c = WHITE;
            }
            // Keyhole: dot (16,19) r 2 + slot x 16, y 20..25.
            let kx = x as f32 - 16.0;
            let ky = y as f32 - 19.0;
            if (kx * kx + ky * ky).sqrt() <= 2.0 || (x == 16 && (20..25).contains(&y)) {
                c = DARK;
            }
            let i = ((y * S + x) * 4) as usize;
            px[i..i + 4].copy_from_slice(&c);
        }
    }
    (px, S, S)
}

/// Close-to-tray interception: hide instead of quitting. Pure.
pub fn should_hide_on_close(tray_enabled: bool, close_requested: bool, allow_close: bool) -> bool {
    tray_enabled && close_requested && !allow_close
}

/// Case-insensitive name+issuer substring filter, sorted by (name, issuer).
/// Pure: unit-tested below.
pub fn filter(accounts: &[totp::Account], query: &str) -> Vec<usize> {
    let q = query.to_lowercase();
    let mut vis: Vec<usize> = accounts
        .iter()
        .enumerate()
        .filter(|(_, a)| {
            (a.name.clone() + " " + &a.issuer)
                .to_lowercase()
                .contains(&q)
        })
        .map(|(i, _)| i)
        .collect();
    vis.sort_by(|&i, &j| {
        let (a, b) = (&accounts[i], &accounts[j]);
        a.name
            .to_lowercase()
            .cmp(&b.name.to_lowercase())
            .then(a.issuer.to_lowercase().cmp(&b.issuer.to_lowercase()))
    });
    vis
}

/// Reject accidental double add/import: same name+issuer or same
/// secret-with-identical-settings. Mirrors Go `duplicateError`.
pub fn duplicate_error(lang: &str, accounts: &[totp::Account]) -> Option<String> {
    use std::collections::HashMap;
    let mut seen_id: HashMap<String, usize> = HashMap::new();
    let mut seen_secret: HashMap<String, usize> = HashMap::new();
    for (i, a) in accounts.iter().enumerate() {
        let id = format!(
            "{}\x00{}",
            a.name.trim().to_lowercase(),
            a.issuer.trim().to_lowercase()
        );
        if let Some(&j) = seen_id.get(&id) {
            return Some(i18n::get(
                lang,
                "dup.account",
                &[a.name.clone().into(), (j + 1).into(), (i + 1).into()],
            ));
        }
        seen_id.insert(id, i);
        let sid = format!(
            "{}\x00{}\x00{}\x00{}",
            a.secret, a.digits, a.period, a.algorithm
        );
        if let Some(&j) = seen_secret.get(&sid) {
            return Some(i18n::get(
                lang,
                "dup.secret",
                &[(j + 1).into(), (i + 1).into()],
            ));
        }
        seen_secret.insert(sid, i);
    }
    None
}

enum Bg {
    Kdf(Result<vault::Session, String>),
    Qr(Result<totp::Account, String>),
}

/// System-tray handles. The icon must stay alive while shown; menu items are
/// kept for id matching and label refresh on language change.
struct TrayState {
    _icon: tray_icon::TrayIcon,
    show: tray_icon::menu::MenuItem,
    lock: tray_icon::menu::MenuItem,
    quit: tray_icon::menu::MenuItem,
}

#[derive(PartialEq, Eq)]
enum Screen {
    Login,
    Main,
}

#[derive(Default)]
struct LoginState {
    create: bool,
    blocked: Option<String>,
    password: String,
    confirm: String,
    message: String,
    busy: bool,
    focused: bool,
}

#[derive(Default)]
struct AccountForm {
    is_edit: bool,
    index: usize,
    orig: Option<totp::Account>,
    name: String,
    issuer: String,
    secret: String,
    digits: String,
    period: String,
    algorithm: String,
}

#[derive(Default)]
struct SettingsForm {
    idle: String,
    hide: bool,
    lock_focus: bool,
    copy_select: bool,
    compact: bool,
    contrast: bool,
    tray: bool,
    font_idx: usize,
    lang_idx: usize,
    theme_idx: usize,
    new_pw: String,
    repeat_pw: String,
}

enum Dialog {
    None,
    Account(AccountForm),
    Import(String),
    ExportConfirm { uri: String },
    ExportQr { uri: String },
    Backup(String),
    DeleteConfirm { index: usize, label: String },
    Settings(SettingsForm),
    About,
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemeMode {
    #[default]
    System,
    Light,
    Dark,
}

impl ThemeMode {
    pub fn from_str(s: &str) -> Self {
        match s {
            "light" => Self::Light,
            "dark" => Self::Dark,
            _ => Self::System,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }
    fn index(self) -> usize {
        match self {
            Self::System => 0,
            Self::Light => 1,
            Self::Dark => 2,
        }
    }
    fn resolve(self) -> bool {
        match self {
            Self::System => system_dark_mode(),
            Self::Light => false,
            Self::Dark => true,
        }
    }
}

pub struct TotpApp {
    path: String,
    lang: String,
    theme_mode: ThemeMode,
    dark: bool,
    screen: Screen,
    login: LoginState,
    session: Option<vault::Session>,
    accounts: Vec<totp::Account>,
    visible: Vec<usize>,
    selected: Option<usize>,
    search: String,
    status: String,
    idle_minutes: u64,
    hide_codes: bool,
    lock_on_focus: bool,
    copy_on_select: bool,
    compact: bool,
    high_contrast: bool,
    font_scale: f32,
    pinned: HashSet<String>,
    clipboard: String,
    clipboard_until: Option<Instant>,
    last_activity: Instant,
    last_wall: i64,
    dialog: Dialog,
    bg_rx: Option<Receiver<Bg>>,
    qr_reading: bool,
    qr_tex_uri: String,
    qr_tex: Option<egui::TextureHandle>,
    tray_enabled: bool,
    tray: Option<TrayState>,
    window_visible: bool,
    allow_close: bool,
}

impl TotpApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        path: String,
        lang: String,
        theme_mode: ThemeMode,
    ) -> Self {
        install_fonts(&cc.egui_ctx);
        let dark = theme_mode.resolve();
        apply_theme(&cc.egui_ctx, dark, false);
        let mut app = Self {
            path,
            lang,
            theme_mode,
            dark,
            screen: Screen::Login,
            login: LoginState::default(),
            session: None,
            accounts: vec![],
            visible: vec![],
            selected: None,
            search: String::new(),
            status: String::new(),
            idle_minutes: 5,
            hide_codes: false,
            lock_on_focus: false,
            copy_on_select: false,
            compact: false,
            high_contrast: false,
            font_scale: 1.0,
            pinned: HashSet::new(),
            clipboard: String::new(),
            clipboard_until: None,
            last_activity: Instant::now(),
            last_wall: now_unix(),
            dialog: Dialog::None,
            bg_rx: None,
            qr_reading: false,
            qr_tex_uri: String::new(),
            qr_tex: None,
            tray_enabled: false,
            tray: None,
            window_visible: true,
            allow_close: false,
        };
        app.refresh_login_mode();
        app
    }

    fn t(&self, key: &str, args: &[i18n::Arg]) -> String {
        i18n::get(&self.lang, key, args)
    }
    fn tn(&self, n: i64, one: &str, other: &str, args: &[i18n::Arg]) -> String {
        i18n::count(&self.lang, n, one, other, args)
    }
    fn err_text(&self, msg: &str) -> String {
        i18n::err_text(&self.lang, &msg.to_string())
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
        self.last_wall = now_unix();
    }

    fn show_err(&mut self, msg: String) {
        self.dialog = Dialog::Error(self.err_text(&msg));
    }

    fn idle_str(&self) -> String {
        format!("{}m0s", self.idle_minutes)
    }

    fn refresh_login_mode(&mut self) {
        self.login = LoginState::default();
        match std::fs::metadata(&self.path) {
            Err(_) => self.login.create = true,
            Ok(md) => {
                if md.is_dir() {
                    self.login.blocked = Some(self.t("login.is_dir", &[]));
                } else {
                    self.login.create = false;
                }
            }
        }
    }

    fn lock(&mut self) {
        // Wipe secrets best-effort, close dialogs, drop the session.
        if let Dialog::Account(_) = &mut self.dialog {
            // secret field dropped with the dialog.
        }
        self.dialog = Dialog::None;
        self.session = None;
        self.accounts.clear();
        self.visible.clear();
        self.selected = None;
        self.search.clear();
        self.pinned.clear();
        self.bg_rx = None;
        self.qr_reading = false;
        self.qr_tex = None;
        self.qr_tex_uri.clear();
        self.clear_clipboard();
        self.screen = Screen::Login;
        self.refresh_login_mode();
    }

    fn clear_clipboard(&mut self) {
        if !self.clipboard.is_empty()
            && let Ok(mut cb) = arboard::Clipboard::new()
            && matches!(cb.get_text(), Ok(t) if t == self.clipboard)
        {
            let _ = cb.set_text("");
        }
        self.clipboard.clear();
        self.clipboard_until = None;
    }

    fn apply_filter(&mut self) {
        self.selected = None;
        self.reorder_visible();
        let idle = self.idle_str();
        if self.search.trim().is_empty() {
            let n = self.accounts.len() as i64;
            self.status = self.tn(
                n,
                "status.accounts_one",
                "status.accounts_other",
                &[n.into(), self.path.clone().into(), idle.into()],
            );
        } else {
            let v = self.visible.len() as i64;
            let n = self.accounts.len() as i64;
            self.status = self.tn(
                v,
                "status.filtered_one",
                "status.filtered_other",
                &[v.into(), n.into(), self.path.clone().into(), idle.into()],
            );
        }
    }

    /// Rebuild `visible` from the current filter without dropping selection
    /// (used after pin toggles). Status text is left untouched.
    fn reorder_visible(&mut self) {
        let base = filter(&self.accounts, &self.search);
        self.visible = order_pinned(&self.accounts, &base, &self.pinned);
    }

    fn save(&mut self, accounts: Vec<totp::Account>) -> bool {
        // Best-effort auto-`.bak` of the previous ciphertext before every
        // overwrite (same bytes, same password). Never blocks the save.
        let bak_src = self.path.clone();
        if std::path::Path::new(&bak_src).exists() {
            let _ = backup_vault_file(&bak_src, &backup_dest_default(&bak_src));
        }
        let Some(sess) = self.session.as_mut() else {
            return false;
        };
        if let Some(msg) = duplicate_error(&self.lang, &accounts) {
            // Already translated by duplicate_error via i18n::get.
            self.dialog = Dialog::Error(msg);
            return false;
        }
        if let Err(e) = sess.save(accounts) {
            self.show_err(e.to_string());
            return false;
        }
        self.accounts = self
            .session
            .as_ref()
            .map(|s| s.accounts())
            .unwrap_or_default();
        self.apply_filter();
        true
    }

    fn copy_code(&mut self) {
        self.touch();
        let idx = match self.selected {
            Some(i) if self.session.is_some() => i,
            _ => return,
        };
        if idx >= self.accounts.len() {
            return;
        }
        match totp::code(&self.accounts[idx], now_unix()) {
            Ok((c, _)) => {
                if let Ok(mut cb) = arboard::Clipboard::new() {
                    let _ = cb.set_text(c.clone());
                }
                self.clipboard = c;
                self.clipboard_until = Some(Instant::now() + Duration::from_secs(15));
                self.status = self.t("status.copied", &[]);
            }
            Err(e) => self.show_err(e.0),
        }
    }

    fn submit_login(&mut self) {
        if self.login.busy || self.login.blocked.is_some() {
            return;
        }
        let pw = std::mem::take(&mut self.login.password);
        let confirm = std::mem::take(&mut self.login.confirm);
        if self.login.create {
            if pw != confirm {
                self.login.message = self.t("login.mismatch", &[]);
                return;
            }
            if let Err(e) = vault::check_password(&pw) {
                self.login.message = self.err_text(&e.to_string());
                return;
            }
        }
        self.login.busy = true;
        self.login.message = self.t("login.deriving", &[]);
        let (tx, rx) = channel();
        self.bg_rx = Some(rx);
        let path = self.path.clone();
        let create = self.login.create;
        std::thread::spawn(move || {
            let r = if create {
                vault::Session::create(std::path::Path::new(&path), &pw)
            } else {
                vault::Session::unlock(std::path::Path::new(&path), &pw)
            };
            let _ = tx.send(Bg::Kdf(r.map_err(|e| e.to_string())));
        });
    }

    fn poll_bg(&mut self) {
        let mut results = Vec::new();
        if let Some(rx) = &self.bg_rx {
            while let Ok(r) = rx.try_recv() {
                results.push(r);
            }
        }
        for r in results {
            match r {
                Bg::Kdf(Ok(sess)) => {
                    if self.screen != Screen::Login {
                        continue;
                    }
                    self.session = Some(sess);
                    self.accounts = self
                        .session
                        .as_ref()
                        .map(|s| s.accounts())
                        .unwrap_or_default();
                    self.login.busy = false;
                    self.login.message.clear();
                    self.touch();
                    self.screen = Screen::Main;
                    self.apply_filter();
                }
                Bg::Kdf(Err(e)) => {
                    if self.screen == Screen::Login {
                        self.login.busy = false;
                        self.login.focused = false; // refocus the password field
                        self.login.message = self.err_text(&e);
                    }
                }
                Bg::Qr(Ok(a)) => {
                    self.qr_reading = false;
                    if self.session.is_none() {
                        continue;
                    }
                    self.touch();
                    let mut accs = self
                        .session
                        .as_ref()
                        .map(|s| s.accounts())
                        .unwrap_or_default();
                    accs.push(a);
                    self.save(accs);
                }
                Bg::Qr(Err(e)) => {
                    self.qr_reading = false;
                    if self.session.is_none() {
                        continue;
                    }
                    if e == "no-image" {
                        self.show_err(self.t("qr.no_image", &[]));
                    } else if let Some(inner) = e.strip_prefix("invalid:") {
                        let msg = self.t("qr.invalid", &[self.err_text(inner).into()]);
                        self.dialog = Dialog::Error(msg);
                    } else {
                        self.show_err(e);
                    }
                }
            }
        }
    }

    fn paste_qr(&mut self) {
        self.touch();
        if self.session.is_none() {
            return;
        }
        self.status = self.t("status.qr_reading", &[]);
        self.qr_reading = true;
        let (tx, rx) = channel();
        self.bg_rx = Some(rx);
        std::thread::spawn(move || {
            let out: Result<totp::Account, String> = (|| {
                let mut cb =
                    arboard::Clipboard::new().map_err(|e| format!("clipboard unavailable: {e}"))?;
                let img = cb.get_image().map_err(|_| "no-image".to_string())?;
                let rgba = image::RgbaImage::from_raw(
                    img.width as u32,
                    img.height as u32,
                    img.bytes.into_owned(),
                )
                .ok_or_else(|| "clipboard does not hold a readable PNG/JPEG image".to_string())?;
                let mut png = Vec::new();
                let mut cur = std::io::Cursor::new(&mut png);
                image::DynamicImage::ImageRgba8(rgba)
                    .write_to(&mut cur, image::ImageFormat::Png)
                    .map_err(|_| "clipboard does not hold a readable PNG/JPEG image".to_string())?;
                let text = totpvault_qrimg::decode_bytes(&png).map_err(|e| e.to_string())?;
                totp::parse_uri(&text).map_err(|e| format!("invalid:{}", e.0))
            })();
            let _ = tx.send(Bg::Qr(out));
        });
    }

    fn ensure_tray(&mut self) -> Result<(), String> {
        let (rgba, w, h) = tray_icon_rgba();
        let icon = tray_icon::Icon::from_rgba(rgba, w, h).map_err(|e| format!("tray icon: {e}"))?;
        let menu = tray_icon::menu::Menu::new();
        let show = tray_icon::menu::MenuItem::new(self.t("tray.show", &[]), true, None);
        let lock = tray_icon::menu::MenuItem::new(self.t("btn.lock", &[]), true, None);
        let quit = tray_icon::menu::MenuItem::new(self.t("btn.quit", &[]), true, None);
        menu.append_items(&[&show, &lock, &quit])
            .map_err(|e| format!("tray menu: {e}"))?;
        let handle = tray_icon::TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("TOTP Vault")
            .with_icon(icon)
            .build()
            .map_err(|e| format!("system tray unavailable: {e}"))?;
        self.tray = Some(TrayState {
            _icon: handle,
            show,
            lock,
            quit,
        });
        Ok(())
    }

    fn refresh_tray_texts(&self) {
        if let Some(t) = &self.tray {
            t.show.set_text(self.t("tray.show", &[]));
            t.lock.set_text(self.t("btn.lock", &[]));
            t.quit.set_text(self.t("btn.quit", &[]));
        }
    }

    fn toggle_window(&mut self, ui: &mut egui::Ui) {
        self.touch();
        self.window_visible = !self.window_visible;
        ui.ctx()
            .send_viewport_cmd(egui::ViewportCommand::Visible(self.window_visible));
        if self.window_visible {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Focus);
        }
    }

    /// Tray icon lifecycle + menu/click events, polled every repaint (500ms).
    /// Runs on the UI thread, like everything else in `TotpApp`.
    fn poll_tray(&mut self, ui: &mut egui::Ui) {
        // Close-to-tray: hide instead of quitting, when enabled.
        if should_hide_on_close(
            self.tray_enabled,
            ui.ctx().input(|i| i.viewport().close_requested()),
            self.allow_close,
        ) {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Visible(false));
            self.window_visible = false;
            return;
        }
        if !self.tray_enabled {
            return;
        }
        if self.tray.is_none()
            && let Err(e) = self.ensure_tray()
        {
            // No tray on this desktop (e.g. GNOME without the AppIndicator
            // extension, headless/CI): fall back to plain window mode, once.
            self.tray_enabled = false;
            self.status = self.t("tray.unavailable", &[]);
            self.show_err(e);
            return;
        }
        while let Ok(ev) = tray_icon::TrayIconEvent::receiver().try_recv() {
            // Single toggle per click: press (Down) and release (Up) arrive
            // as separate events on some backends; KSNI sends Up only.
            if matches!(
                ev,
                tray_icon::TrayIconEvent::Click {
                    button: tray_icon::MouseButton::Left,
                    button_state: tray_icon::MouseButtonState::Up,
                    ..
                }
            ) {
                self.toggle_window(ui);
            }
        }
        while let Ok(ev) = tray_icon::menu::MenuEvent::receiver().try_recv() {
            let (show_id, lock_id, quit_id) = match &self.tray {
                Some(t) => (t.show.id(), t.lock.id(), t.quit.id()),
                None => continue,
            };
            if ev.id == show_id {
                self.toggle_window(ui);
            } else if ev.id == lock_id {
                self.touch();
                self.lock();
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Visible(true));
                self.window_visible = true;
            } else if ev.id == quit_id {
                self.allow_close = true;
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    fn tick(&mut self) {
        self.poll_bg();
        let now = Instant::now();
        if let Some(until) = self.clipboard_until
            && now >= until
        {
            self.clear_clipboard();
        }
        if self.session.is_some() {
            // Offline clock-jump guard: a backwards jump means TOTP codes are
            // likely wrong. Warn once and re-baseline; never touch() here so
            // the idle timer keeps working (see touch() discipline).
            let now_w = now_unix();
            if clock_went_backwards(self.last_wall, now_w) {
                self.last_wall = now_w;
                self.status = self.t("status.clock_warn", &[]);
            }
            let idle = Duration::from_secs(self.idle_minutes * 60);
            let wall_elapsed = now_unix() - self.last_wall;
            if now.duration_since(self.last_activity) >= idle
                || (self.last_wall != 0 && wall_elapsed >= idle.as_secs() as i64)
            {
                self.lock();
            }
        }
    }
}

fn load_font_file(path: &std::path::Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok().filter(|b| !b.is_empty())
}

fn install_fonts(ctx: &egui::Context) {
    // System UI fonts first (native look), egui's embedded fonts stay as
    // fallback. CJK and other scripts are served on demand by the
    // `system_fonts` provider (memory-mapped, not copied into RAM), so we
    // deliberately do NOT preload the ~16 MB msyh.ttc here.
    let mut defs = egui::FontDefinitions::default();
    let mut prop_first: Vec<String> = Vec::new();
    let mut mono_first: Vec<String> = Vec::new();

    if let Ok(windir) = std::env::var("WINDIR") {
        let fonts = std::path::Path::new(&windir).join("Fonts");
        for (file, name, mono) in [
            ("segoeui.ttf", "segoe-ui", false),
            ("seguisb.ttf", "segoe-ui-sb", false),
            ("consola.ttf", "consolas", true),
        ] {
            if let Some(bytes) = load_font_file(&fonts.join(file)) {
                defs.font_data
                    .insert(name.to_string(), egui::FontData::from_owned(bytes).into());
                if mono {
                    mono_first.push(name.to_string());
                } else {
                    prop_first.push(name.to_string());
                }
            }
        }
        // CJK and other scripts are served on demand by the `system_fonts`
        // provider (memory-mapped, not copied into RAM): no preload here.
    } else {
        // Linux: Noto Sans as the native-ish proportional font.
        let file = "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf";
        if let Some(bytes) = load_font_file(std::path::Path::new(file)) {
            defs.font_data.insert(
                "noto-sans".to_string(),
                egui::FontData::from_owned(bytes).into(),
            );
            prop_first.push("noto-sans".to_string());
        }
    }

    for (fam, first) in [
        (egui::FontFamily::Proportional, &prop_first),
        (egui::FontFamily::Monospace, &mono_first),
    ] {
        let mut chain = first.clone();
        if let Some(existing) = defs.families.get(&fam) {
            chain.extend(existing.iter().cloned());
        }
        defs.families.insert(fam, chain);
    }
    ctx.set_fonts(defs);
}

/// Brand accent: teal padlock (matches the app icon).
pub const ACCENT_LIGHT: egui::Color32 = egui::Color32::from_rgb(13, 148, 136);
pub const ACCENT_DARK: egui::Color32 = egui::Color32::from_rgb(45, 212, 191);
pub const DANGER: egui::Color32 = egui::Color32::from_rgb(220, 60, 60);

/// Refined theme on top of the egui light/dark base: teal accent, rounded
/// controls, comfortable type sizes. `hc` is the optional high-contrast
/// override (pure black/white text, maximum-contrast selection).
fn apply_theme(ctx: &egui::Context, dark: bool, hc: bool) {
    let mut style = (*ctx.global_style()).clone();
    let mut visuals = if dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    let accent = if dark { ACCENT_DARK } else { ACCENT_LIGHT };
    visuals.selection.bg_fill = accent;
    visuals.selection.stroke.color = egui::Color32::WHITE;
    visuals.hyperlink_color = accent;
    if hc {
        visuals.override_text_color = Some(if dark {
            egui::Color32::WHITE
        } else {
            egui::Color32::BLACK
        });
        visuals.selection.bg_fill = if dark {
            egui::Color32::YELLOW
        } else {
            egui::Color32::BLUE
        };
        visuals.selection.stroke.color = if dark {
            egui::Color32::BLACK
        } else {
            egui::Color32::WHITE
        };
    }
    for w in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        w.corner_radius = egui::CornerRadius::same(7);
    }
    visuals.window_corner_radius = egui::CornerRadius::same(10);
    visuals.menu_corner_radius = egui::CornerRadius::same(10);
    style.visuals = visuals;
    style.spacing.button_padding = egui::vec2(14.0, 8.0);
    style.spacing.item_spacing = egui::vec2(10.0, 10.0);
    style.spacing.indent = 20.0;
    if let Some(fid) = style.text_styles.get_mut(&egui::TextStyle::Body) {
        fid.size = 15.0;
    }
    if let Some(fid) = style.text_styles.get_mut(&egui::TextStyle::Button) {
        fid.size = 14.0;
    }
    if let Some(fid) = style.text_styles.get_mut(&egui::TextStyle::Heading) {
        fid.size = 24.0;
    }
    if let Some(fid) = style.text_styles.get_mut(&egui::TextStyle::Monospace) {
        fid.size = 15.0;
    }
    ctx.set_global_style(style);
}

/// Avatar palette: muted 500-level tones readable on light and dark.
const AVATAR_COLORS: [egui::Color32; 12] = [
    egui::Color32::from_rgb(13, 148, 136),
    egui::Color32::from_rgb(37, 99, 235),
    egui::Color32::from_rgb(124, 58, 237),
    egui::Color32::from_rgb(219, 39, 119),
    egui::Color32::from_rgb(234, 88, 12),
    egui::Color32::from_rgb(22, 163, 74),
    egui::Color32::from_rgb(220, 38, 38),
    egui::Color32::from_rgb(8, 145, 178),
    egui::Color32::from_rgb(202, 138, 4),
    egui::Color32::from_rgb(101, 163, 13),
    egui::Color32::from_rgb(79, 70, 229),
    egui::Color32::from_rgb(190, 24, 93),
];

fn avatar_color(key: &str) -> egui::Color32 {
    let mut h: u64 = 0xcbf29ce4842225;
    for b in key.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    AVATAR_COLORS[(h % AVATAR_COLORS.len() as u64) as usize]
}

/// Pushpin toggle, vector-drawn: ★/☆ are tofu in Segoe UI/Consolas, so the
/// pin is painted (filled = pinned, outline = free) instead of relying on a
/// font glyph. Pure paint, no I/O.
fn pin_button(ui: &mut egui::Ui, pinned: bool, accent: egui::Color32, tip: &str) -> egui::Response {
    let size = egui::vec2(26.0, 26.0);
    let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::click());
    let p = ui.painter_at(rect);
    let c = rect.center();
    if ui.rect_contains_pointer(rect) {
        p.circle_filled(
            c,
            12.0,
            egui::Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), 32),
        );
    }
    let head = c + egui::vec2(0.0, -5.0);
    if pinned {
        p.circle_filled(head, 5.5, accent);
        p.line_segment(
            [head + egui::vec2(0.0, 5.5), head + egui::vec2(0.0, 11.5)],
            egui::Stroke::new(2.5, accent),
        );
    } else {
        let weak = ui.visuals().weak_text_color();
        p.circle_stroke(head, 5.5, egui::Stroke::new(2.0, weak));
        p.line_segment(
            [head + egui::vec2(0.0, 5.5), head + egui::vec2(0.0, 11.5)],
            egui::Stroke::new(2.0, weak),
        );
    }
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(tip)
}

/// Colored disc with the account's initial (issuer, else name).
fn avatar(ui: &mut egui::Ui, account: &totp::Account, diameter: f32) {
    let key = if account.issuer.is_empty() {
        account.name.clone()
    } else {
        account.issuer.clone()
    };
    let ch = key
        .chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or("?".to_string());
    let (rect, _) = ui.allocate_exact_size(egui::vec2(diameter, diameter), egui::Sense::hover());
    let p = ui.painter_at(rect);
    p.circle_filled(rect.center(), diameter / 2.0, avatar_color(&key));
    p.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        ch,
        egui::FontId::proportional(diameter * 0.45),
        egui::Color32::WHITE,
    );
}

/// Countdown ring: track + remaining arc + seconds in the middle.
fn countdown_ring(ui: &mut egui::Ui, frac: f32, seconds: i64, accent: egui::Color32) {
    let size = 52.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let p = ui.painter_at(rect);
    let c = rect.center();
    let r = size / 2.0 - 4.0;
    let faint = egui::Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), 48);
    p.circle_stroke(c, r, egui::Stroke::new(4.0, faint));
    let danger = seconds <= 5;
    let col = if danger { DANGER } else { accent };
    if frac > 0.001 {
        let steps = 40;
        let start = -std::f32::consts::FRAC_PI_2;
        let mut pts = Vec::with_capacity(steps + 1);
        for i in 0..=steps {
            let a = start + frac * std::f32::consts::TAU * (i as f32 / steps as f32);
            pts.push(c + egui::vec2(a.cos(), a.sin()) * r);
        }
        p.line(pts, egui::Stroke::new(4.0, col));
    }
    p.text(
        c,
        egui::Align2::CENTER_CENTER,
        seconds.to_string(),
        egui::FontId::monospace(13.0),
        if danger {
            DANGER
        } else {
            ui.visuals().weak_text_color()
        },
    );
}

/// Teal padlock mark for the login screen (echoes the app icon).
fn lock_mark(ui: &mut egui::Ui, dark: bool) {
    let size = 72.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    let p = ui.painter_at(rect);
    let accent = if dark { ACCENT_DARK } else { ACCENT_LIGHT };
    p.rect_filled(
        egui::Rect::from_min_size(rect.min + egui::vec2(12.0, 30.0), egui::vec2(48.0, 36.0)),
        9.0,
        accent,
    );
    let sc = egui::pos2(rect.center().x, rect.min.y + 30.0);
    let mut pts = Vec::with_capacity(24);
    for i in 0..=24 {
        let a = std::f32::consts::PI + std::f32::consts::PI * (i as f32 / 24.0);
        pts.push(sc + egui::vec2(a.cos(), a.sin()) * 13.0);
    }
    p.line(pts, egui::Stroke::new(6.0, accent));
    let kc = egui::pos2(rect.center().x, rect.min.y + 46.0);
    p.circle_filled(kc, 4.5, egui::Color32::WHITE);
    p.rect_filled(
        egui::Rect::from_min_size(kc + egui::vec2(-2.0, 2.0), egui::vec2(4.0, 8.0)),
        1.5,
        egui::Color32::WHITE,
    );
}

#[cfg(windows)]
fn system_dark_mode() -> bool {
    // HKCU\...\Personalize\AppsUseLightTheme: 0 = dark, 1 = light.
    std::process::Command::new("reg")
        .args([
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            "/v",
            "AppsUseLightTheme",
        ])
        .output()
        .map(|o| {
            let s = String::from_utf8_lossy(&o.stdout);
            s.lines()
                .any(|l| l.contains("AppsUseLightTheme") && l.trim_end().ends_with("0x0"))
        })
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn system_dark_mode() -> bool {
    false
}

impl eframe::App for TotpApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.tick();
        ui.ctx().request_repaint_after(Duration::from_millis(500));
        ui.ctx().set_pixels_per_point(self.font_scale);

        if self.screen == Screen::Login {
            self.show_login(ui);
            return;
        }
        // Optional per-session hardening: lock as soon as the window loses
        // focus (e.g. Alt+Tab). Checked here — not in tick() — so it reacts
        // within one repaint without disturbing the idle timer.
        let focus_lost = ui.ctx().input(|i| i.viewport().focused == Some(false));
        if self.lock_on_focus && self.session.is_some() && focus_lost {
            self.lock();
            return;
        }
        self.poll_tray(ui);
        // Shortcuts: Enter / Ctrl+C copy the selected code when no text field
        // or dialog consumes the keystroke.
        let mut want_copy = false;
        let wants_kb = ui.ctx().egui_wants_keyboard_input();
        let no_dialog = matches!(self.dialog, Dialog::None);
        // NOTE: egui-winit turns Ctrl+C / Ctrl+Insert into `Event::Copy`
        // (meant for text fields), so no `Key::C` event ever reaches us. When
        // no text field or dialog owns the keystroke, a Copy event means the
        // user hit the copy shortcut: copy the selected code, like Go does.
        ui.ctx().input(|i| {
            if no_dialog && !wants_kb && i.events.iter().any(|e| matches!(e, egui::Event::Copy)) {
                want_copy = true;
            }
        });
        ui.input_mut(|i| {
            if no_dialog && !wants_kb && i.consume_key(egui::Modifiers::NONE, egui::Key::Enter) {
                want_copy = true;
            }
        });
        if want_copy {
            self.copy_code();
        }
        self.show_main(ui);
        self.show_dialog(ui);
    }
}

impl TotpApp {
    fn show_login(&mut self, ui: &mut egui::Ui) {
        egui::CentralPanel::default().show(&mut *ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(36.0);
                lock_mark(ui, self.dark);
                ui.add_space(4.0);
                ui.heading(self.t("app.title", &[]));
                let title = if self.login.create {
                    self.t("login.create", &[])
                } else {
                    self.t("login.unlock", &[])
                };
                ui.label(egui::RichText::new(title.clone()).size(16.0).strong());
                ui.add_space(10.0);
                if let Some(blocked) = self.login.blocked.clone() {
                    ui.label(self.t("login.cannot_read", &[]));
                    ui.label(blocked);
                    ui.horizontal(|ui| {
                        if ui.button(self.t("btn.retry", &[])).clicked() {
                            self.touch();
                            self.refresh_login_mode();
                        }
                        if ui.button(self.t("btn.quit", &[])).clicked() {
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                    return;
                }
                let ph_hint = self.t("login.ph_master", &[]);
                if !self.login.focused {
                    // Focus the password field on arrival, like Go's Canvas().Focus.
                    self.login.focused = true;
                    ui.memory_mut(|m| {
                        m.request_focus(egui::Id::unique("login-password"));
                    });
                }
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.login.password)
                        .id(egui::Id::unique("login-password"))
                        .password(true)
                        .hint_text(ph_hint)
                        .desired_width(300.0),
                );
                if self.login.create {
                    let rp_hint = self.t("login.ph_repeat", &[]);
                    ui.add(
                        egui::TextEdit::singleline(&mut self.login.confirm)
                            .password(true)
                            .hint_text(rp_hint)
                            .desired_width(300.0),
                    );
                    ui.label(self.t("login.hint1", &[]));
                    ui.label(self.t("login.hint2", &[]));
                    let s = password_strength(&self.login.password);
                    ui.label(self.t("pw.strength", &[i64::from(s).into()]));
                }
                if !self.login.password.is_empty() && caps_lock_on() {
                    ui.label(self.t("login.caps", &[]));
                }
                ui.add_enabled_ui(!self.login.busy, |ui| {
                    let accent = if self.dark { ACCENT_DARK } else { ACCENT_LIGHT };
                    let btn = egui::Button::new(
                        egui::RichText::new(title.clone())
                            .size(15.0)
                            .strong()
                            .color(egui::Color32::WHITE),
                    )
                    .fill(accent)
                    .min_size(egui::vec2(300.0, 0.0));
                    if ui.add(btn).clicked()
                        || (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                    {
                        self.touch();
                        self.submit_login();
                    }
                });
                if !self.login.message.is_empty() {
                    ui.label(&self.login.message);
                }
                ui.add_space(16.0);
                ui.weak(self.t("login.footer", &[]));
            });
        });
    }

    fn show_main(&mut self, ui: &mut egui::Ui) {
        let mut copy = false;
        let mut add = false;
        let mut edit = false;
        let mut delete = false;
        let mut export = false;
        let mut import = false;
        let mut paste_qr = false;
        let mut backup = false;
        let mut settings = false;
        let mut about = false;
        let mut lock = false;

        egui::Panel::top("toolbar").show(&mut *ui, |ui| {
            ui.horizontal(|ui| {
                ui.strong(self.t("main.title", &[]));
            });
            let search_hint = self.t("main.search", &[]);
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text(search_hint)
                    .desired_width(300.0),
            );
            if resp.changed() {
                self.touch();
                self.apply_filter();
            }
            ui.horizontal(|ui| {
                let sel = self.selected.is_some();
                let accent = if self.dark { ACCENT_DARK } else { ACCENT_LIGHT };
                if ui
                    .add_enabled(
                        true,
                        egui::Button::new(
                            egui::RichText::new(self.t("btn.add", &[]))
                                .strong()
                                .color(egui::Color32::WHITE),
                        )
                        .fill(accent),
                    )
                    .clicked()
                {
                    add = true;
                }
                if ui
                    .add_enabled(sel, egui::Button::new(self.t("btn.copy", &[])))
                    .clicked()
                {
                    copy = true;
                }
                if ui
                    .add_enabled(sel, egui::Button::new(self.t("btn.edit", &[])))
                    .clicked()
                {
                    edit = true;
                }
                if ui
                    .add_enabled(sel, egui::Button::new(self.t("btn.delete", &[])))
                    .clicked()
                {
                    delete = true;
                }
                if ui
                    .add_enabled(sel, egui::Button::new(self.t("btn.export", &[])))
                    .clicked()
                {
                    export = true;
                }
                ui.menu_button("⋯", |ui| {
                    if ui.button(self.t("btn.import_uri", &[])).clicked() {
                        import = true;
                        ui.close();
                    }
                    let qr_label = if self.qr_reading {
                        format!("{} …", self.t("btn.paste_qr", &[]))
                    } else {
                        self.t("btn.paste_qr", &[])
                    };
                    if ui
                        .add_enabled(!self.qr_reading, egui::Button::new(qr_label))
                        .clicked()
                    {
                        paste_qr = true;
                        ui.close();
                    }
                    if ui.button(self.t("btn.backup", &[])).clicked() {
                        backup = true;
                        ui.close();
                    }
                    if ui.button(self.t("btn.settings", &[])).clicked() {
                        settings = true;
                        ui.close();
                    }
                    if ui.button(self.t("btn.about", &[])).clicked() {
                        about = true;
                        ui.close();
                    }
                    if ui.button(self.t("btn.lock", &[])).clicked() {
                        lock = true;
                        ui.close();
                    }
                });
            });
        });
        egui::Panel::bottom("status").show(&mut *ui, |ui| {
            ui.label(&self.status);
        });
        egui::CentralPanel::default().show(&mut *ui, |ui| {
            egui::ScrollArea::vertical().show(&mut *ui, |ui| {
                let now = now_unix();
                let accent = if self.dark { ACCENT_DARK } else { ACCENT_LIGHT };
                let pin_tip = self.t("pin.tip", &[]);
                let mut clicked: Option<usize> = None;
                let mut double_clicked: Option<usize> = None;
                let mut toggle_pin: Option<usize> = None;
                for &ai in &self.visible.clone() {
                    let a = &self.accounts[ai];
                    let is_sel = self.selected == Some(ai);
                    let is_pin = self.pinned.contains(&pin_key(&a.name, &a.issuer));
                    let (code_txt, rem) = if self.hide_codes && !is_sel {
                        ("••• •••".to_string(), (a.period - now % a.period) as f32)
                    } else {
                        match totp::code(a, now) {
                            Ok((c, r)) => (spaced(&c), r as f32),
                            Err(_) => (self.t("main.code_error", &[]), 0.0),
                        }
                    };
                    let frac = (rem / a.period as f32).clamp(0.0, 1.0);
                    let pad = if self.compact { 4.0 } else { 10.0 };
                    let av = if self.compact { 28.0 } else { 40.0 };
                    let code_sz = if self.compact { 16.0 } else { 20.0 };
                    let mut frame = egui::Frame::group(ui.style())
                        .inner_margin(pad)
                        .corner_radius(10.0);
                    if is_sel {
                        let w = if self.high_contrast { 3.0 } else { 2.0 };
                        frame = frame.stroke(egui::Stroke::new(w, accent));
                    }
                    let inner = frame.show(&mut *ui, |ui| {
                        ui.horizontal(|ui| {
                            avatar(ui, a, av);
                            ui.add_space(4.0);
                            ui.vertical(|ui| {
                                ui.label(egui::RichText::new(&a.name).size(15.0).strong());
                                if a.issuer.is_empty() {
                                    ui.weak("—");
                                } else {
                                    ui.weak(&a.issuer);
                                }
                                if is_sel && let Some(nc) = next_code_text(a, now) {
                                    ui.weak(self.t("main.next", &[nc.into()]));
                                }
                            });
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    countdown_ring(ui, frac, rem as i64, accent);
                                    ui.add_space(6.0);
                                    if pin_button(ui, is_pin, accent, &pin_tip).clicked() {
                                        toggle_pin = Some(ai);
                                    }
                                    ui.add_space(4.0);
                                    let code = if rem <= 5.0 {
                                        egui::RichText::new(&code_txt)
                                            .monospace()
                                            .size(code_sz)
                                            .strong()
                                            .color(DANGER)
                                    } else {
                                        egui::RichText::new(&code_txt)
                                            .monospace()
                                            .size(code_sz)
                                            .strong()
                                    };
                                    ui.label(code);
                                },
                            );
                        });
                    });
                    // Frames don't sense clicks on their own: make the whole
                    // card interactive (click = select, double-click = copy).
                    let card_id = ui.make_persistent_id(("account-card", ai));
                    let resp = ui
                        .interact(inner.response.rect, card_id, egui::Sense::click())
                        .on_hover_cursor(egui::CursorIcon::PointingHand);
                    if resp.double_clicked() {
                        double_clicked = Some(ai);
                    } else if resp.clicked() {
                        clicked = Some(ai);
                    }
                    ui.add_space(4.0);
                }
                if let Some(ai) = double_clicked {
                    self.touch();
                    self.selected = Some(ai);
                    self.copy_code();
                } else if let Some(ai) = clicked {
                    self.touch();
                    self.selected = Some(ai);
                    if self.copy_on_select {
                        self.copy_code();
                    }
                }
                if let Some(ai) = toggle_pin {
                    self.touch();
                    if let Some(a) = self.accounts.get(ai).cloned() {
                        let k = pin_key(&a.name, &a.issuer);
                        if !self.pinned.remove(&k) {
                            self.pinned.insert(k);
                        }
                        self.reorder_visible();
                    }
                }
            });
        });

        if copy {
            self.copy_code();
        }
        if add {
            self.touch();
            self.dialog = Dialog::Account(AccountForm {
                digits: "6".into(),
                period: "30".into(),
                algorithm: "SHA1".into(),
                ..Default::default()
            });
        }
        if edit {
            self.touch();
            if let Some(i) = self.selected
                && let Some(a) = self.accounts.get(i).cloned()
            {
                self.dialog = Dialog::Account(AccountForm {
                    is_edit: true,
                    index: i,
                    orig: Some(a.clone()),
                    name: a.name,
                    issuer: a.issuer,
                    secret: a.secret,
                    digits: a.digits.to_string(),
                    period: a.period.to_string(),
                    algorithm: a.algorithm,
                });
            }
        }
        if delete {
            self.touch();
            if let Some(i) = self.selected
                && let Some(a) = self.accounts.get(i)
            {
                let mut label = a.name.clone();
                if !a.issuer.is_empty() {
                    label = format!("{label} ({})", a.issuer);
                }
                self.dialog = Dialog::DeleteConfirm { index: i, label };
            }
        }
        if export {
            self.touch();
            if let Some(i) = self.selected
                && let Some(a) = self.accounts.get(i)
            {
                match totp::provisioning_uri(a) {
                    Ok(uri) => self.dialog = Dialog::ExportConfirm { uri },
                    Err(e) => self.show_err(e.0),
                }
            }
        }
        if import {
            self.touch();
            self.dialog = Dialog::Import(String::new());
        }
        if paste_qr {
            self.paste_qr();
        }
        if backup {
            self.touch();
            self.dialog = Dialog::Backup(backup_dest_default(&self.path));
        }
        if settings {
            self.touch();
            self.dialog = Dialog::Settings(SettingsForm {
                idle: self.idle_minutes.to_string(),
                hide: self.hide_codes,
                lock_focus: self.lock_on_focus,
                copy_select: self.copy_on_select,
                compact: self.compact,
                contrast: self.high_contrast,
                tray: self.tray_enabled,
                font_idx: font_idx_from_scale(self.font_scale),
                lang_idx: i18n::index_of(&self.lang),
                theme_idx: self.theme_mode.index(),
                ..Default::default()
            });
        }
        if about {
            self.touch();
            self.dialog = Dialog::About;
        }
        if lock {
            self.lock();
        }
    }

    fn show_dialog(&mut self, ui: &mut egui::Ui) {
        match std::mem::replace(&mut self.dialog, Dialog::None) {
            Dialog::None => {}
            Dialog::Account(mut f) => {
                let mut open = true;
                let mut save = false;
                let mut cancel = false;
                egui::Window::new(self.t(if f.is_edit { "acct.edit" } else { "acct.add" }, &[]))
                    .open(&mut open)
                    .show(&*ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(self.t("acct.f_account", &[]));
                            ui.text_edit_singleline(&mut f.name);
                        });
                        ui.horizontal(|ui| {
                            ui.label(self.t("acct.f_issuer", &[]));
                            ui.text_edit_singleline(&mut f.issuer);
                        });
                        ui.horizontal(|ui| {
                            ui.label(self.t("acct.f_secret", &[]));
                            ui.text_edit_singleline(&mut f.secret);
                        });
                        ui.horizontal(|ui| {
                            ui.label(self.t("acct.f_digits", &[]));
                            egui::ComboBox::from_id_salt("digits")
                                .selected_text(&f.digits)
                                .show_ui(ui, |ui| {
                                    for d in ["6", "8"] {
                                        ui.selectable_value(&mut f.digits, d.to_string(), d);
                                    }
                                });
                            ui.label(self.t("acct.f_period", &[]));
                            ui.text_edit_singleline(&mut f.period);
                        });
                        ui.horizontal(|ui| {
                            ui.label(self.t("acct.f_algo", &[]));
                            egui::ComboBox::from_id_salt("algo")
                                .selected_text(&f.algorithm)
                                .show_ui(ui, |ui| {
                                    for al in ["SHA1", "SHA256", "SHA512"] {
                                        ui.selectable_value(&mut f.algorithm, al.to_string(), al);
                                    }
                                });
                        });
                        ui.horizontal(|ui| {
                            if ui.button(self.t("btn.save", &[])).clicked() {
                                save = true;
                            }
                            if ui.button(self.t("btn.cancel", &[])).clicked() {
                                cancel = true;
                            }
                        });
                    });
                if !open || cancel {
                    // dropped: secret cleared with the form.
                } else if save {
                    self.touch();
                    if self.session.is_none() {
                        // locked meanwhile: abort.
                    } else {
                        match f.period.trim().parse::<i64>() {
                            Ok(p) if p >= 1 => {
                                let n: u32 = f.digits.parse().unwrap_or(6);
                                match totp::normalize(totp::Account {
                                    name: f.name.clone(),
                                    issuer: f.issuer.clone(),
                                    secret: f.secret.clone(),
                                    digits: n,
                                    period: p,
                                    algorithm: f.algorithm.clone(),
                                }) {
                                    Ok(a) => {
                                        let mut accs = self
                                            .session
                                            .as_ref()
                                            .map(|s| s.accounts())
                                            .unwrap_or_default();
                                        if !f.is_edit {
                                            accs.push(a);
                                        } else if f.index >= accs.len()
                                            || Some(&accs[f.index]) != f.orig.as_ref()
                                        {
                                            self.show_err(self.t("acct.err_changed", &[]));
                                        } else {
                                            accs[f.index] = a;
                                        }
                                        if !matches!(self.dialog, Dialog::Error(_)) {
                                            self.save(accs);
                                        }
                                    }
                                    Err(e) => self.show_err(e.0),
                                }
                            }
                            _ => self.show_err(self.t("acct.err_period", &[])),
                        }
                    }
                } else {
                    self.dialog = Dialog::Account(f);
                }
            }
            Dialog::Import(mut uri) => {
                let mut open = true;
                let mut cancelled = false;
                let mut go = false;
                egui::Window::new(self.t("import.title", &[]))
                    .open(&mut open)
                    .show(&*ui, |ui| {
                        ui.text_edit_singleline(&mut uri);
                        ui.horizontal(|ui| {
                            if ui.button(self.t("btn.import", &[])).clicked() {
                                go = true;
                            }
                            if ui.button(self.t("btn.cancel", &[])).clicked() {
                                cancelled = true;
                            }
                        });
                    });
                if go {
                    self.touch();
                    if self.session.is_some() {
                        match totp::parse_uri(&uri) {
                            Ok(a) => {
                                let mut accs = self
                                    .session
                                    .as_ref()
                                    .map(|s| s.accounts())
                                    .unwrap_or_default();
                                accs.push(a);
                                self.save(accs);
                            }
                            Err(e) => self.show_err(e.0),
                        }
                    }
                } else if open && !cancelled {
                    self.dialog = Dialog::Import(uri);
                }
            }
            Dialog::ExportConfirm { uri } => {
                let mut open = true;
                let mut cancelled = false;
                let mut go = false;
                let mut show_qr = false;
                egui::Window::new(self.t("export.title", &[]))
                    .open(&mut open)
                    .show(&*ui, |ui| {
                        ui.label(self.t("export.msg", &[]));
                        ui.horizontal(|ui| {
                            if ui.button(self.t("btn.copy", &[])).clicked() {
                                go = true;
                            }
                            if ui.button(self.t("export.show_qr", &[])).clicked() {
                                show_qr = true;
                            }
                            if ui.button(self.t("btn.cancel", &[])).clicked() {
                                cancelled = true;
                            }
                        });
                    });
                if show_qr {
                    self.touch();
                    if self.session.is_some() {
                        self.qr_tex = None;
                        self.qr_tex_uri.clear();
                        self.dialog = Dialog::ExportQr { uri };
                    }
                } else if go {
                    self.touch();
                    if self.session.is_some() {
                        if let Ok(mut cb) = arboard::Clipboard::new() {
                            let _ = cb.set_text(uri.clone());
                        }
                        self.clipboard = uri;
                        self.clipboard_until = Some(Instant::now() + Duration::from_secs(15));
                        self.status = self.t("status.uri_copied", &[]);
                    }
                } else if open && !cancelled {
                    self.dialog = Dialog::ExportConfirm { uri };
                }
            }
            Dialog::ExportQr { uri } => {
                let mut open = true;
                let mut cancelled = false;
                let mut copy = false;
                let (tex, err) = if self.qr_tex_uri == uri
                    && let Some(h) = self.qr_tex.clone()
                {
                    (Some(h), None)
                } else {
                    match qr_color_image(&uri) {
                        Ok(img) => {
                            let h = ui.ctx().load_texture(
                                "export-qr",
                                img,
                                egui::TextureOptions::NEAREST,
                            );
                            self.qr_tex = Some(h.clone());
                            self.qr_tex_uri = uri.clone();
                            (Some(h), None)
                        }
                        Err(e) => (None, Some(e)),
                    }
                };
                if let Some(e) = err {
                    self.show_err(e);
                } else {
                    egui::Window::new(self.t("export.qr_title", &[]))
                        .open(&mut open)
                        .show(&*ui, |ui| {
                            if let Some(h) = &tex {
                                ui.image(h);
                            }
                            ui.label(self.t("export.qr_hint", &[]));
                            ui.horizontal(|ui| {
                                if ui.button(self.t("btn.copy", &[])).clicked() {
                                    copy = true;
                                }
                                if ui.button(self.t("btn.close", &[])).clicked() {
                                    cancelled = true;
                                }
                            });
                        });
                    if copy {
                        self.touch();
                        if self.session.is_some() {
                            if let Ok(mut cb) = arboard::Clipboard::new() {
                                let _ = cb.set_text(uri.clone());
                            }
                            self.clipboard = uri;
                            self.clipboard_until = Some(Instant::now() + Duration::from_secs(15));
                            self.status = self.t("status.uri_copied", &[]);
                        }
                    } else if open && !cancelled {
                        self.dialog = Dialog::ExportQr { uri };
                    }
                }
            }
            Dialog::Backup(mut dest) => {
                let mut open = true;
                let mut cancelled = false;
                let mut go = false;
                egui::Window::new(self.t("backup.title", &[]))
                    .open(&mut open)
                    .show(&*ui, |ui| {
                        ui.label(self.t("backup.msg", &[]));
                        ui.horizontal(|ui| {
                            ui.label(self.t("backup.dest", &[]));
                            ui.text_edit_singleline(&mut dest);
                        });
                        ui.horizontal(|ui| {
                            if ui.button(self.t("btn.backup", &[])).clicked() {
                                go = true;
                            }
                            if ui.button(self.t("btn.cancel", &[])).clicked() {
                                cancelled = true;
                            }
                        });
                    });
                if go {
                    self.touch();
                    match backup_vault_file(&self.path, &dest) {
                        Ok(_) => {
                            self.status = self.t("status.backup_ok", &[dest.clone().into()]);
                        }
                        Err(e) => self.show_err(e.to_string()),
                    }
                } else if open && !cancelled {
                    self.dialog = Dialog::Backup(dest);
                }
            }
            Dialog::DeleteConfirm { index, label } => {
                let mut open = true;
                let mut cancelled = false;
                let mut go = false;
                egui::Window::new(self.t("delete.title", &[]))
                    .open(&mut open)
                    .show(&*ui, |ui| {
                        ui.label(self.t("delete.msg", &[label.clone().into()]));
                        ui.horizontal(|ui| {
                            if ui.button(self.t("btn.delete", &[])).clicked() {
                                go = true;
                            }
                            if ui.button(self.t("btn.cancel", &[])).clicked() {
                                cancelled = true;
                            }
                        });
                    });
                if go {
                    self.touch();
                    if self.session.is_some() {
                        let accs = self
                            .session
                            .as_ref()
                            .map(|s| s.accounts())
                            .unwrap_or_default();
                        let orig = self.accounts.get(index).cloned();
                        match orig {
                            Some(o) if accs.get(index) == Some(&o) => {
                                let mut accs = accs;
                                accs.remove(index);
                                self.selected = None;
                                self.save(accs);
                            }
                            _ => self.show_err(self.t("acct.err_changed", &[])),
                        }
                    }
                } else if open && !cancelled {
                    self.dialog = Dialog::DeleteConfirm { index, label };
                }
            }
            Dialog::Settings(mut f) => {
                let mut open = true;
                let mut cancelled = false;
                let mut go = false;
                egui::Window::new(self.t("settings.title", &[]))
                    .open(&mut open)
                    .show(&*ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(self.t("settings.idle", &[]));
                            egui::ComboBox::from_id_salt("idle")
                                .selected_text(&f.idle)
                                .show_ui(ui, |ui| {
                                    for m in ["1", "2", "5", "10", "15"] {
                                        ui.selectable_value(&mut f.idle, m.to_string(), m);
                                    }
                                });
                        });
                        ui.checkbox(&mut f.hide, self.t("settings.hide", &[]));
                        ui.checkbox(&mut f.lock_focus, self.t("settings.lock_focus", &[]));
                        ui.checkbox(&mut f.copy_select, self.t("settings.copy_select", &[]));
                        ui.checkbox(&mut f.compact, self.t("settings.compact", &[]));
                        ui.checkbox(&mut f.contrast, self.t("settings.contrast", &[]));
                        ui.checkbox(&mut f.tray, self.t("settings.tray", &[]));
                        let font_labels = ["90%", "100%", "115%", "130%"];
                        let font_cur = font_labels
                            .get(f.font_idx)
                            .cloned()
                            .unwrap_or("100%")
                            .to_string();
                        ui.horizontal(|ui| {
                            ui.label(self.t("settings.font", &[]));
                            egui::ComboBox::from_id_salt("font")
                                .selected_text(font_cur)
                                .show_ui(ui, |ui| {
                                    for (i, nm) in font_labels.iter().enumerate() {
                                        ui.selectable_value(&mut f.font_idx, i, nm.to_string());
                                    }
                                });
                        });
                        let tags = i18n::supported();
                        let names: Vec<String> = tags
                            .iter()
                            .map(|t| i18n::native_name(t).to_string())
                            .collect();
                        let cur = names.get(f.lang_idx).cloned().unwrap_or_default();
                        ui.horizontal(|ui| {
                            ui.label(self.t("settings.lang", &[]));
                            egui::ComboBox::from_id_salt("lang")
                                .selected_text(cur)
                                .show_ui(ui, |ui| {
                                    for (i, nm) in names.iter().enumerate() {
                                        ui.selectable_value(&mut f.lang_idx, i, nm);
                                    }
                                });
                        });
                        let theme_names = [
                            self.t("theme.system", &[]),
                            self.t("theme.light", &[]),
                            self.t("theme.dark", &[]),
                        ];
                        let theme_cur = theme_names.get(f.theme_idx).cloned().unwrap_or_default();
                        ui.horizontal(|ui| {
                            ui.label(self.t("settings.theme", &[]));
                            egui::ComboBox::from_id_salt("theme")
                                .selected_text(theme_cur)
                                .show_ui(ui, |ui| {
                                    for (i, nm) in theme_names.iter().enumerate() {
                                        ui.selectable_value(&mut f.theme_idx, i, nm);
                                    }
                                });
                        });
                        ui.horizontal(|ui| {
                            ui.label(self.t("settings.new_pw", &[]));
                            ui.add(egui::TextEdit::singleline(&mut f.new_pw).password(true));
                        });
                        ui.horizontal(|ui| {
                            ui.label(self.t("settings.repeat_pw", &[]));
                            ui.add(egui::TextEdit::singleline(&mut f.repeat_pw).password(true));
                        });
                        if !f.new_pw.is_empty() {
                            let s = password_strength(&f.new_pw);
                            ui.label(self.t("pw.strength", &[i64::from(s).into()]));
                        }
                        ui.horizontal(|ui| {
                            if ui.button(self.t("btn.save", &[])).clicked() {
                                go = true;
                            }
                            if ui.button(self.t("btn.cancel", &[])).clicked() {
                                cancelled = true;
                            }
                        });
                    });
                if go {
                    self.touch();
                    if self.session.is_none() {
                        // locked meanwhile: abort.
                    } else {
                        if (!f.new_pw.is_empty() || !f.repeat_pw.is_empty())
                            && f.new_pw != f.repeat_pw
                        {
                            self.show_err(self.t("settings.err_mismatch", &[]));
                            self.dialog = Dialog::Settings(f);
                            return;
                        }
                        if (!f.new_pw.is_empty() || !f.repeat_pw.is_empty())
                            && let Some(sess) = self.session.as_mut()
                            && let Err(e) = sess.change_password(&f.new_pw)
                        {
                            let msg = self.err_text(&e.to_string());
                            self.dialog = Dialog::Error(msg);
                            return;
                        }
                        match f.idle.parse::<u64>() {
                            Ok(n) if n > 0 => self.idle_minutes = n,
                            _ => {
                                self.show_err(self.t("settings.err_idle", &[]));
                                self.dialog = Dialog::Settings(f);
                                return;
                            }
                        }
                        self.hide_codes = f.hide;
                        self.lock_on_focus = f.lock_focus;
                        self.copy_on_select = f.copy_select;
                        self.compact = f.compact;
                        self.font_scale = font_scale_from_idx(f.font_idx);
                        let tags = i18n::supported();
                        if let Some(tag) = tags.get(f.lang_idx)
                            && *tag != self.lang
                        {
                            self.lang = tag.to_string();
                            crate::prefs::save_language(tag);
                        }
                        let new_theme = match f.theme_idx {
                            1 => ThemeMode::Light,
                            2 => ThemeMode::Dark,
                            _ => ThemeMode::System,
                        };
                        if new_theme != self.theme_mode {
                            self.theme_mode = new_theme;
                            crate::prefs::save_theme(new_theme.as_str());
                            self.dark = new_theme.resolve();
                            apply_theme(ui.ctx(), self.dark, self.high_contrast);
                        }
                        if self.high_contrast != f.contrast {
                            self.high_contrast = f.contrast;
                            apply_theme(ui.ctx(), self.dark, self.high_contrast);
                        }
                        if f.tray != self.tray_enabled {
                            self.tray_enabled = f.tray;
                            if !f.tray {
                                self.tray = None; // icon removed
                            }
                        }
                        self.refresh_tray_texts();
                        self.apply_filter();
                    }
                } else if open && !cancelled {
                    self.dialog = Dialog::Settings(f);
                }
            }
            Dialog::About => {
                let mut open = true;
                egui::Window::new(self.t("about.title", &[]))
                    .open(&mut open)
                    .show(&*ui, |ui| {
                        ui.label(self.t("about.body", &[self.path.clone().into()]));
                        ui.add_space(8.0);
                        ui.label(self.t("about.keys", &[]));
                    });
                if open {
                    self.dialog = Dialog::About;
                }
            }
            Dialog::Error(msg) => {
                let mut open = true;
                let mut cancelled = false;
                egui::Window::new("!")
                    .open(&mut open)
                    .collapsible(false)
                    .show(&*ui, |ui| {
                        ui.label(&msg);
                        if ui.button(self.t("btn.close", &[])).clicked() {
                            cancelled = true;
                        }
                    });
                if open && !cancelled {
                    self.dialog = Dialog::Error(msg);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acc(name: &str, issuer: &str) -> totp::Account {
        totp::Account {
            name: name.into(),
            issuer: issuer.into(),
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            digits: 6,
            period: 30,
            algorithm: "SHA1".into(),
        }
    }

    #[test]
    fn filter_sorts_and_matches() {
        let all = vec![acc("bob", "B"), acc("Alice", ""), acc("alice", "A")];
        let v = filter(&all, "");
        assert_eq!(v, vec![1, 2, 0]);
        let v = filter(&all, "ali");
        assert_eq!(v, vec![1, 2]);
        let v = filter(&all, "b");
        assert_eq!(v, vec![0]);
    }

    #[test]
    fn duplicates_rejected() {
        let lang = "en";
        assert!(duplicate_error(lang, &[acc("a", "I"), acc("A", "i")]).is_some());
        let same_secret = vec![acc("a", "I"), acc("b", "J")];
        assert!(duplicate_error(lang, &same_secret).is_some());
        let mut diff = vec![acc("a", "I"), acc("b", "J")];
        diff[1].digits = 8;
        assert!(duplicate_error(lang, &diff).is_none());
    }

    #[test]
    fn export_qr_renders_offline() {
        let a = acc("alice", "Example");
        let uri = totp::provisioning_uri(&a).unwrap();
        let img = qr_color_image(&uri).unwrap();
        assert!(!img.pixels.is_empty());
        assert!(img.width() >= 100 && img.height() >= 100);
        // Fail closed on payloads that exceed QR capacity.
        assert!(qr_color_image(&"x".repeat(8000)).is_err());
    }

    #[test]
    fn password_strength_scores_classes() {
        assert_eq!(password_strength(""), 0);
        assert_eq!(password_strength("short"), 0);
        assert_eq!(password_strength("abcdefghijkl"), 1);
        assert_eq!(password_strength("Abcdefghijkl"), 2);
        assert_eq!(password_strength("Abcdefghijk1"), 3);
        assert_eq!(password_strength("Abcdefghijk1!"), 4);
        // Long but single-class stays weak.
        assert_eq!(password_strength("aaaaaaaaaaaaaaaa"), 1);
    }

    #[test]
    fn pin_key_normalizes() {
        assert_eq!(pin_key(" Alice ", "Example"), pin_key("alice", "example"));
        assert_ne!(pin_key("a", "x"), pin_key("a", "y"));
    }

    #[test]
    fn pinned_sort_first() {
        let all = vec![acc("bob", "B"), acc("Alice", ""), acc("alice", "A")];
        let vis = filter(&all, "");
        assert_eq!(vis, vec![1, 2, 0]);
        let mut pinned = HashSet::new();
        pinned.insert(pin_key("bob", "B"));
        let ordered = order_pinned(&all, &vis, &pinned);
        assert_eq!(ordered, vec![0, 1, 2]);
        assert!(order_pinned(&all, &[], &pinned).is_empty());
    }

    #[test]
    fn backup_dest_appends_bak() {
        assert_eq!(backup_dest_default("vault.dat"), "vault.dat.bak");
        assert_eq!(backup_dest_default("a/b/v.dat"), "a/b/v.dat.bak");
    }

    #[test]
    fn clock_backwards_detected() {
        assert!(clock_went_backwards(1000, 900));
        assert!(!clock_went_backwards(1000, 1000));
        assert!(!clock_went_backwards(1000, 1059));
        assert!(!clock_went_backwards(1000, 5000));
        assert!(!clock_went_backwards(0, 900));
    }

    #[test]
    fn font_scale_round_trips() {
        assert!((font_scale_from_idx(0) - 0.9).abs() < 1e-6);
        assert!((font_scale_from_idx(1) - 1.0).abs() < 1e-6);
        assert!((font_scale_from_idx(2) - 1.15).abs() < 1e-6);
        assert!((font_scale_from_idx(3) - 1.3).abs() < 1e-6);
        assert!((font_scale_from_idx(99) - 1.0).abs() < 1e-6);
        assert_eq!(font_idx_from_scale(0.9), 0);
        assert_eq!(font_idx_from_scale(1.0), 1);
        assert_eq!(font_idx_from_scale(1.15), 2);
        assert_eq!(font_idx_from_scale(1.3), 3);
    }

    #[test]
    fn next_code_matches_period_boundary() {
        let a = acc("alice", "Example");
        assert_eq!(a.period, 30);
        let (c30, _) = totp::code(&a, 30).unwrap();
        assert_eq!(next_code_text(&a, 0).unwrap(), spaced(&c30));
        // Same following period anywhere inside the first window.
        assert_eq!(next_code_text(&a, 29).unwrap(), spaced(&c30));
        let (c60, _) = totp::code(&a, 60).unwrap();
        assert_eq!(next_code_text(&a, 30).unwrap(), spaced(&c60));
        assert!(next_code_text(&a, -1).is_none());
        let mut bad = acc("b", "B");
        bad.period = 0;
        assert!(next_code_text(&bad, 100).is_none());
    }

    #[test]
    fn backup_file_round_trip() {
        let dir = std::env::temp_dir();
        let tag = format!(
            "totpvault-baktest-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let src = dir.join(format!("{tag}.dat"));
        let dest = dir.join(format!("{tag}.dat.bak"));
        std::fs::write(&src, b"ciphertext-bytes").unwrap();
        let n = backup_vault_file(src.to_str().unwrap(), dest.to_str().unwrap()).unwrap();
        assert_eq!(n, 16);
        assert_eq!(std::fs::read(&dest).unwrap(), b"ciphertext-bytes");
        std::fs::remove_file(&src).ok();
        std::fs::remove_file(&dest).ok();
        assert!(backup_vault_file("/no/such/dir/v.dat", "/no/such/dir/v.dat.bak").is_err());
    }

    #[test]
    fn tray_icon_pixels_sane() {
        let (px, w, h) = tray_icon_rgba();
        assert_eq!((w, h), (32, 32));
        assert_eq!(px.len(), 32 * 32 * 4);
        let at = |x: u32, y: u32| -> [u8; 4] {
            let i = ((y * w + x) * 4) as usize;
            [px[i], px[i + 1], px[i + 2], px[i + 3]]
        };
        assert_eq!(at(0, 0)[3], 0); // transparent corner
        assert_eq!(at(31, 31)[3], 0);
        assert_eq!(at(14, 22), [255, 255, 255, 255]); // body
        assert_eq!(at(16, 22), [10, 110, 100, 255]); // keyhole slot
        assert_eq!(at(16, 7), [255, 255, 255, 255]); // shackle top
        assert_eq!(at(16, 30), [13, 148, 136, 255]); // teal base
    }

    #[test]
    fn close_hides_only_with_tray() {
        assert!(should_hide_on_close(true, true, false));
        assert!(!should_hide_on_close(true, true, true));
        assert!(!should_hide_on_close(false, true, false));
        assert!(!should_hide_on_close(true, false, false));
    }

    #[test]
    fn new_ui_keys_translated_everywhere() {
        for lang in i18n::supported() {
            for key in [
                "login.caps",
                "main.next",
                "settings.compact",
                "settings.contrast",
                "settings.tray",
                "tray.show",
                "tray.unavailable",
                "pin.tip",
                "btn.backup",
                "backup.title",
                "status.backup_ok",
            ] {
                let s = i18n::get(lang, key, &[0.into(), "x".into()]);
                assert!(!s.is_empty() && s != key, "{key} missing in {lang}");
            }
        }
    }

    #[test]
    fn new_settings_default_off() {
        let f = SettingsForm::default();
        assert!(!f.compact && !f.contrast && !f.lock_focus && !f.copy_select && !f.tray);
    }
}
