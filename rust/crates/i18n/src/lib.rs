//! Offline UI translations. English is the source language; FR/DE/IT/ES/ZH/EL
//! tables are compiled in (generated from the Go `internal/i18n` sources).
//! Backend crates keep returning English errors; the UI translates at the
//! display boundary via [`err_text`], mirroring Go `i18n.ErrText`.

mod tables {
    include!("tables.rs");
}

pub const DEFAULT_LANG: &str = "en";

const SUPPORTED: &[&str] = &["en", "de", "el", "es", "fr", "it", "zh"];

const NATIVE_NAMES: &[(&str, &str)] = &[
    ("en", "English"),
    ("de", "Deutsch"),
    ("el", "Ελληνικά"),
    ("es", "Español"),
    ("fr", "Français"),
    ("it", "Italiano"),
    ("zh", "中文"),
];

pub fn supported() -> Vec<&'static str> {
    SUPPORTED.to_vec()
}

pub fn native_name(tag: &str) -> &'static str {
    let n = normalize(tag);
    for (t, name) in NATIVE_NAMES {
        if *t == n {
            return name;
        }
    }
    "English"
}

pub fn index_of(tag: &str) -> usize {
    let n = normalize(tag);
    if n.is_empty() {
        return 0;
    }
    for (i, t) in SUPPORTED.iter().enumerate() {
        if *t == n {
            return i;
        }
    }
    0
}

/// Map locale strings like `fr-FR`, `el_GR.UTF-8`, `zh-Hans` to a supported
/// tag. Returns "" when there is no match.
pub fn normalize(raw: &str) -> String {
    let mut s = raw.trim().to_lowercase();
    if s.is_empty() {
        return String::new();
    }
    s = s.replace('-', "_");
    if let Some(i) = s.find('.') {
        s.truncate(i);
    }
    if let Some(i) = s.find('@') {
        s.truncate(i);
    }
    if s.is_empty() || s == "c" || s == "posix" {
        return String::new();
    }
    let base = s.split('_').next().unwrap_or("").to_string();
    if base == "zh" {
        return "zh".to_string();
    }
    match base.as_str() {
        "en" | "fr" | "de" | "it" | "es" | "el" => base,
        _ => String::new(),
    }
}

/// OS language mapped to a supported tag, or "en".
pub fn detect() -> String {
    if let Some(s) = sys_locale::get_locale() {
        let t = normalize(&s);
        if !t.is_empty() {
            return t;
        }
    }
    for k in ["LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(v) = std::env::var(k) {
            for part in v.split(':') {
                let t = normalize(part);
                if !t.is_empty() {
                    return t;
                }
            }
        }
    }
    DEFAULT_LANG.to_string()
}

fn tag(lang: &str) -> &str {
    let n = normalize(lang);
    if SUPPORTED.contains(&n.as_str()) {
        // Return the canonical tag; leak-free via static match.
        for t in SUPPORTED {
            if *t == n {
                return t;
            }
        }
    }
    DEFAULT_LANG
}

/// Format argument for translated templates.
#[derive(Debug, Clone)]
pub enum Arg {
    Int(i64),
    Str(String),
}

impl From<i64> for Arg {
    fn from(v: i64) -> Self {
        Arg::Int(v)
    }
}
impl From<i32> for Arg {
    fn from(v: i32) -> Self {
        Arg::Int(v as i64)
    }
}
impl From<usize> for Arg {
    fn from(v: usize) -> Self {
        Arg::Int(v as i64)
    }
}
impl From<&str> for Arg {
    fn from(v: &str) -> Self {
        Arg::Str(v.to_string())
    }
}
impl From<String> for Arg {
    fn from(v: String) -> Self {
        Arg::Str(v)
    }
}

/// Go `%q` quoting for display: double quotes, C escapes, printable Unicode
/// kept as-is.
fn go_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{{{:x}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Minimal `Sprintf` for our templates: verbs `%d`, `%s`, `%q` are consumed
/// left to right; `%%` yields `%`.
fn format_tmpl(tmpl: &str, args: &[Arg]) -> String {
    let mut out = String::with_capacity(tmpl.len() + 16);
    let mut it = args.iter();
    let mut chars = tmpl.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('%') => out.push('%'),
            Some(v @ ('d' | 's' | 'q')) => {
                let Some(a) = it.next() else {
                    out.push('%');
                    out.push(v);
                    continue;
                };
                match (v, a) {
                    ('q', Arg::Str(s)) => out.push_str(&go_quote(s)),
                    (_, Arg::Int(n)) => out.push_str(&n.to_string()),
                    (_, Arg::Str(s)) => out.push_str(s),
                }
            }
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

fn lookup(lang: &str, key: &str) -> Option<&'static str> {
    for (k, v) in tables::table(lang) {
        if *k == key {
            return Some(v);
        }
    }
    for (l, pairs) in EXTRA {
        if *l == lang {
            for (k, v) in *pairs {
                if *k == key {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Hand-added keys for the Rust GUI (no Go source): theme switcher labels.
/// Kept separate from the generated tables so `gen_tables.py` stays clean.
const EXTRA: &[(&str, &[(&str, &str)])] = &[
    (
        "en",
        &[
            ("settings.theme", "Theme"),
            ("theme.system", "System"),
            ("theme.light", "Light"),
            ("theme.dark", "Dark"),
        ],
    ),
    (
        "de",
        &[
            ("settings.theme", "Design"),
            ("theme.system", "System"),
            ("theme.light", "Hell"),
            ("theme.dark", "Dunkel"),
        ],
    ),
    (
        "el",
        &[
            ("settings.theme", "Θέμα"),
            ("theme.system", "Σύστημα"),
            ("theme.light", "Φωτεινό"),
            ("theme.dark", "Σκοτεινό"),
        ],
    ),
    (
        "es",
        &[
            ("settings.theme", "Tema"),
            ("theme.system", "Sistema"),
            ("theme.light", "Claro"),
            ("theme.dark", "Oscuro"),
        ],
    ),
    (
        "fr",
        &[
            ("settings.theme", "Thème"),
            ("theme.system", "Système"),
            ("theme.light", "Clair"),
            ("theme.dark", "Sombre"),
        ],
    ),
    (
        "it",
        &[
            ("settings.theme", "Tema"),
            ("theme.system", "Sistema"),
            ("theme.light", "Chiaro"),
            ("theme.dark", "Scuro"),
        ],
    ),
    (
        "zh",
        &[
            ("settings.theme", "主题"),
            ("theme.system", "跟随系统"),
            ("theme.light", "浅色"),
            ("theme.dark", "深色"),
        ],
    ),
];

/// Translated template for `key` in `lang`, formatted with `args`.
/// Unknown languages fall back to English; unknown keys return the key.
pub fn get(lang: &str, key: &str, args: &[Arg]) -> String {
    let t = tag(lang);
    if let Some(s) = lookup(t, key) {
        return format_tmpl(s, args);
    }
    if let Some(s) = lookup("en", key) {
        return format_tmpl(s, args);
    }
    key.to_string()
}

/// Singular/plural selection. French treats 0 as singular; Chinese tables
/// are identical. The count renders through `%d`.
pub fn count(lang: &str, n: i64, one_key: &str, other_key: &str, args: &[Arg]) -> String {
    let t = tag(lang);
    if t == "fr" {
        if n <= 1 {
            return get(t, one_key, args);
        }
        return get(t, other_key, args);
    }
    if n == 1 {
        return get(t, one_key, args);
    }
    get(t, other_key, args)
}

const ERR_KEYS: &[(&str, &str)] = &[
    (
        "use at least 12 characters for the master password",
        "err.pw_short",
    ),
    ("master password is too long", "err.pw_long"),
    ("wrong master password or damaged vault", "err.auth"),
    (
        "vault changed on disk; lock and unlock again before saving",
        "err.changed",
    ),
    ("vault is locked", "err.locked"),
    ("vault exceeds size limit", "err.size"),
    ("unsupported or damaged vault format", "err.format"),
    ("invalid vault payload", "err.payload"),
    ("too many accounts", "err.many"),
    ("account name is required (maximum 256 bytes)", "err.name"),
    ("digits must be 6 or 8", "err.digits"),
    (
        "period must be between 1 and 300 seconds",
        "err.period_range",
    ),
    ("algorithm must be SHA1, SHA256 or SHA512", "err.algo"),
    ("secret is too long", "err.secret_long"),
    (
        "secret must be valid Base32 containing at least 10 bytes",
        "err.secret_b32",
    ),
    ("clock is before the Unix epoch", "err.epoch"),
    ("URI is too long", "err.uri_long"),
    ("expected otpauth://totp/... URI", "err.uri_expected"),
    ("invalid URI query", "err.uri_query"),
    ("invalid URI label", "err.uri_label"),
    ("issuer does not match label", "err.uri_issuer"),
    ("invalid digits", "err.uri_digits"),
    ("invalid period", "err.uri_period"),
    ("passwords do not match", "settings.err_mismatch"),
    ("Passwords do not match", "login.mismatch"),
    ("invalid idle minutes", "settings.err_idle"),
    (
        "account changed meanwhile; reopen and try again",
        "acct.err_changed",
    ),
    ("image is empty", "qr.img_empty"),
    ("image exceeds 5 MiB limit", "qr.img_big"),
    (
        "clipboard does not hold a readable PNG/JPEG image",
        "qr.img_unreadable",
    ),
    ("image dimensions out of range", "qr.img_dims"),
    ("image has too many pixels", "qr.img_pixels"),
    ("no QR code found in image", "qr.not_found"),
    ("could not decode QR code", "qr.decode_fail"),
    ("QR code holds no text", "qr.no_text"),
    ("QR code content is too long", "qr.too_long"),
];

const ERR_PREFIXES: &[(&str, &str)] = &[
    ("invalid account: ", "err.invalid_account"),
    ("QR code is not a valid TOTP URI: ", "qr.invalid"),
    ("clipboard unavailable: ", "qr.clip_unavail"),
];

fn err_key(msg: &str) -> Option<(String, Vec<Arg>)> {
    for (prefix, key) in ERR_PREFIXES {
        if let Some(rest) = msg.strip_prefix(prefix) {
            let inner = err_text_inner("en", rest);
            return Some((key.to_string(), vec![Arg::Str(inner)]));
        }
    }
    if let Some(rest) = msg.strip_prefix("duplicate ") {
        if let Some(param) = rest.strip_suffix(" parameter") {
            return Some(("err.uri_dup".to_string(), vec![Arg::Str(param.to_string())]));
        }
    }
    if let Some(param) = msg.strip_prefix("unsupported parameter: ") {
        return Some((
            "err.uri_unsupported".to_string(),
            vec![Arg::Str(param.to_string())],
        ));
    }
    for (text, key) in ERR_KEYS {
        if *text == msg {
            return Some((key.to_string(), vec![]));
        }
    }
    None
}

fn err_text_inner(lang: &str, msg: &str) -> String {
    if let Some((key, args)) = err_key(msg) {
        return get(lang, &key, &args);
    }
    msg.to_string()
}

/// Translate a backend/UI error for display. Unknown errors keep their text.
pub fn err_text(lang: &str, err: &dyn std::fmt::Display) -> String {
    err_text_inner(lang, &err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verbs(tmpl: &str) -> Vec<char> {
        let mut out = Vec::new();
        let mut chars = tmpl.chars();
        while let Some(c) = chars.next() {
            if c == '%' {
                match chars.next() {
                    Some('%') => {}
                    Some(v) => out.push(v),
                    None => {}
                }
            }
        }
        out
    }

    #[test]
    fn all_keys_present_and_verbs_match() {
        let en = tables::table("en");
        assert!(!en.is_empty());
        for lang in SUPPORTED {
            let t = tables::table(lang);
            assert_eq!(t.len(), en.len(), "key count {lang}");
            for (k, v) in en {
                let got = t.iter().find(|(kk, _)| kk == k);
                assert!(got.is_some(), "missing {k} in {lang}");
                assert_eq!(
                    verbs(got.unwrap().1),
                    verbs(v),
                    "verb mismatch {k} in {lang}"
                );
            }
        }
    }

    #[test]
    fn fallback_and_lookup() {
        assert_eq!(get("xx", "btn.close", &[]), "Close");
        assert_eq!(get("de", "no.such.key", &[]), "no.such.key");
        assert_eq!(get("el", "btn.close", &[]), "Κλείσιμο");
        assert_eq!(
            get(
                "en",
                "status.accounts_other",
                &[2.into(), "/p".into(), "5m".into()]
            ),
            "2 accounts • /p • auto-lock after 5m idle"
        );
    }

    #[test]
    fn plural_rules() {
        let one = count(
            "en",
            1,
            "status.accounts_one",
            "status.accounts_other",
            &[1.into(), "p".into(), "5m".into()],
        );
        let other = count(
            "en",
            2,
            "status.accounts_one",
            "status.accounts_other",
            &[2.into(), "p".into(), "5m".into()],
        );
        assert!(one.starts_with("1 account "));
        assert!(other.starts_with("2 accounts "));
        let fr0 = count(
            "fr",
            0,
            "status.accounts_one",
            "status.accounts_other",
            &[0.into(), "p".into(), "5m".into()],
        );
        let fr2 = count(
            "fr",
            2,
            "status.accounts_one",
            "status.accounts_other",
            &[2.into(), "p".into(), "5m".into()],
        );
        assert_ne!(fr0, fr2);
    }

    #[test]
    fn normalize_and_index() {
        assert_eq!(normalize("fr-FR"), "fr");
        assert_eq!(normalize("el_GR.UTF-8"), "el");
        assert_eq!(normalize("zh-Hans"), "zh");
        assert_eq!(normalize("C"), "");
        assert_eq!(index_of("de"), 1);
        assert_eq!(index_of("xx"), 0);
        assert_eq!(native_name("el"), "Ελληνικά");
    }

    #[test]
    fn extra_keys_covered_everywhere() {
        let keys: Vec<&str> = EXTRA[0].1.iter().map(|(k, _)| *k).collect();
        for (lang, pairs) in EXTRA {
            let have: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
            assert_eq!(have, keys, "extra key mismatch in {lang}");
            for k in &keys {
                assert!(!get(lang, k, &[]).is_empty());
            }
        }
    }

    #[test]
    fn error_translation() {
        let e = totpvault_error_sample();
        assert_eq!(
            err_text("el", &e),
            "λάθος κύριος κωδικός ή κατεστραμμένο θησαυροφυλάκιο"
        );
        assert_eq!(err_text("en", &e), "wrong master password or damaged vault");
        let dup = DupParam("digits".to_string());
        assert_eq!(err_text("en", &dup), "duplicate digits parameter");
        let wrapped = WrappedAccount("digits must be 6 or 8".to_string());
        assert!(err_text("en", &wrapped).starts_with("invalid account: "));
        let unknown = Unknown("something new".to_string());
        assert_eq!(err_text("de", &unknown), "something new");
    }

    use std::fmt;
    struct SampleErr(&'static str);
    impl fmt::Display for SampleErr {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }
    fn totpvault_error_sample() -> impl fmt::Display {
        SampleErr("wrong master password or damaged vault")
    }
    struct DupParam(String);
    impl fmt::Display for DupParam {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "duplicate {} parameter", self.0)
        }
    }
    struct WrappedAccount(String);
    impl fmt::Display for WrappedAccount {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "invalid account: {}", self.0)
        }
    }
    struct Unknown(String);
    impl fmt::Display for Unknown {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.0)
        }
    }
}
