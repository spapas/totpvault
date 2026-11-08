//! egui controller: login -> main list -> dialogs. Single UI thread; KDF and
//! QR-clipboard work run on background threads and report back via channel.
//!
//! Session discipline mirrors `archived/go/internal/ui`: all writes go through
//! `save()`; dialogs abort when the session was locked meanwhile; edit/delete
//! verify the account index still holds the same account; only explicit
//! actions (typing, selection, buttons) reset the idle timer.

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
    clipboard: String,
    clipboard_until: Option<Instant>,
    last_activity: Instant,
    last_wall: i64,
    dialog: Dialog,
    bg_rx: Option<Receiver<Bg>>,
    qr_reading: bool,
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
        apply_theme(&cc.egui_ctx, dark);
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
            clipboard: String::new(),
            clipboard_until: None,
            last_activity: Instant::now(),
            last_wall: now_unix(),
            dialog: Dialog::None,
            bg_rx: None,
            qr_reading: false,
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
        self.bg_rx = None;
        self.qr_reading = false;
        self.clear_clipboard();
        self.screen = Screen::Login;
        self.refresh_login_mode();
    }

    fn clear_clipboard(&mut self) {
        if !self.clipboard.is_empty() {
            if let Ok(mut cb) = arboard::Clipboard::new() {
                if matches!(cb.get_text(), Ok(t) if t == self.clipboard) {
                    let _ = cb.set_text("");
                }
            }
        }
        self.clipboard.clear();
        self.clipboard_until = None;
    }

    fn apply_filter(&mut self) {
        self.selected = None;
        self.visible = filter(&self.accounts, &self.search);
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

    fn save(&mut self, accounts: Vec<totp::Account>) -> bool {
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

    fn tick(&mut self) {
        self.poll_bg();
        let now = Instant::now();
        if let Some(until) = self.clipboard_until {
            if now >= until {
                self.clear_clipboard();
            }
        }
        if self.session.is_some() {
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
        for file in ["/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf"] {
            if let Some(bytes) = load_font_file(std::path::Path::new(file)) {
                defs.font_data.insert(
                    "noto-sans".to_string(),
                    egui::FontData::from_owned(bytes).into(),
                );
                prop_first.push("noto-sans".to_string());
            }
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
/// controls, comfortable type sizes.
fn apply_theme(ctx: &egui::Context, dark: bool) {
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

        if self.screen == Screen::Login {
            self.show_login(ui);
            return;
        }
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
                    .add_enabled(
                        sel,
                        egui::Button::new(format!("{}", self.t("btn.copy", &[]))),
                    )
                    .clicked()
                {
                    copy = true;
                }
                if ui
                    .add_enabled(
                        sel,
                        egui::Button::new(format!("{}", self.t("btn.edit", &[]))),
                    )
                    .clicked()
                {
                    edit = true;
                }
                if ui
                    .add_enabled(
                        sel,
                        egui::Button::new(format!("{}", self.t("btn.delete", &[]))),
                    )
                    .clicked()
                {
                    delete = true;
                }
                if ui
                    .add_enabled(
                        sel,
                        egui::Button::new(format!("{}", self.t("btn.export", &[]))),
                    )
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
                let mut clicked: Option<usize> = None;
                let mut double_clicked: Option<usize> = None;
                for &ai in &self.visible.clone() {
                    let a = &self.accounts[ai];
                    let is_sel = self.selected == Some(ai);
                    let (code_txt, rem) = if self.hide_codes && !is_sel {
                        ("••• •••".to_string(), (a.period - now % a.period) as f32)
                    } else {
                        match totp::code(a, now) {
                            Ok((c, r)) => (spaced(&c), r as f32),
                            Err(_) => (self.t("main.code_error", &[]), 0.0),
                        }
                    };
                    let frac = (rem / a.period as f32).clamp(0.0, 1.0);
                    let mut frame = egui::Frame::group(ui.style())
                        .inner_margin(10.0)
                        .corner_radius(10.0);
                    if is_sel {
                        frame = frame.stroke(egui::Stroke::new(2.0, accent));
                    }
                    let inner = frame.show(&mut *ui, |ui| {
                        ui.horizontal(|ui| {
                            avatar(ui, a, 40.0);
                            ui.add_space(4.0);
                            ui.vertical(|ui| {
                                ui.label(egui::RichText::new(&a.name).size(15.0).strong());
                                if a.issuer.is_empty() {
                                    ui.weak("—");
                                } else {
                                    ui.weak(&a.issuer);
                                }
                            });
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    countdown_ring(ui, frac, rem as i64, accent);
                                    ui.add_space(6.0);
                                    let code = if rem <= 5.0 {
                                        egui::RichText::new(&code_txt)
                                            .monospace()
                                            .size(20.0)
                                            .strong()
                                            .color(DANGER)
                                    } else {
                                        egui::RichText::new(&code_txt)
                                            .monospace()
                                            .size(20.0)
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
        if settings {
            self.touch();
            self.dialog = Dialog::Settings(SettingsForm {
                idle: self.idle_minutes.to_string(),
                hide: self.hide_codes,
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
                    .show(&mut *ui, |ui| {
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
                    .show(&mut *ui, |ui| {
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
                egui::Window::new(self.t("export.title", &[]))
                    .open(&mut open)
                    .show(&mut *ui, |ui| {
                        ui.label(self.t("export.msg", &[]));
                        ui.horizontal(|ui| {
                            if ui.button(self.t("btn.copy", &[])).clicked() {
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
            Dialog::DeleteConfirm { index, label } => {
                let mut open = true;
                let mut cancelled = false;
                let mut go = false;
                egui::Window::new(self.t("delete.title", &[]))
                    .open(&mut open)
                    .show(&mut *ui, |ui| {
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
                    .show(&mut *ui, |ui| {
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
                        if !f.new_pw.is_empty() || !f.repeat_pw.is_empty() {
                            if f.new_pw != f.repeat_pw {
                                self.show_err(self.t("settings.err_mismatch", &[]));
                                self.dialog = Dialog::Settings(f);
                                return;
                            }
                            if let Some(sess) = self.session.as_mut() {
                                if let Err(e) = sess.change_password(&f.new_pw) {
                                    let msg = self.err_text(&e.to_string());
                                    self.dialog = Dialog::Error(msg);
                                    return;
                                }
                            }
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
                        let tags = i18n::supported();
                        if let Some(tag) = tags.get(f.lang_idx) {
                            if *tag != self.lang {
                                self.lang = tag.to_string();
                                crate::prefs::save_language(tag);
                            }
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
                            apply_theme(ui.ctx(), self.dark);
                        }
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
                    .show(&mut *ui, |ui| {
                        ui.label(self.t("about.body", &[self.path.clone().into()]));
                    });
                if open {
                    self.dialog = Dialog::About;
                }
            }
            Dialog::Error(msg) => {
                let mut open = true;
                let mut cancelled = false;
                egui::Window::new("⚠")
                    .open(&mut open)
                    .collapsible(false)
                    .show(&mut *ui, |ui| {
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
}
