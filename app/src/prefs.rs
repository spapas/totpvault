//! Non-secret UI preferences: interface language tag + theme mode.
use std::path::PathBuf;

fn prefs_path() -> Option<PathBuf> {
    dirs::config_dir().map(|mut p| {
        p.push("TotpVault");
        p.push("prefs.json");
        p
    })
}

fn load_all() -> serde_json::Map<String, serde_json::Value> {
    let Some(p) = prefs_path() else {
        return Default::default();
    };
    std::fs::read(p)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

fn save_all(map: &serde_json::Map<String, serde_json::Value>) {
    let Some(p) = prefs_path() else { return };
    if let Some(dir) = p.parent() {
        if std::fs::create_dir_all(dir).is_err() {
            return;
        }
    }
    let _ = std::fs::write(p, serde_json::Value::Object(map.clone()).to_string());
}

fn load_key(key: &str) -> Option<String> {
    load_all().get(key)?.as_str().map(|s| s.to_string())
}

fn save_key(key: &str, val: &str) {
    let mut map = load_all();
    map.insert(key.to_string(), serde_json::Value::String(val.to_string()));
    save_all(&map);
}

pub fn load_language() -> Option<String> {
    let tag = load_key("language")?;
    let t = totpvault_i18n::normalize(&tag);
    if t.is_empty() { None } else { Some(t) }
}

pub fn save_language(tag: &str) {
    save_key("language", tag);
}

/// "system" | "light" | "dark", or None when unset/invalid.
pub fn load_theme() -> Option<String> {
    match load_key("theme")?.as_str() {
        "system" | "light" | "dark" => load_key("theme"),
        _ => None,
    }
}

pub fn save_theme(mode: &str) {
    save_key("theme", mode);
}
