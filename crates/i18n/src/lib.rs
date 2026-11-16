//! Offline UI translations. English is the source language; FR/DE/IT/ES/ZH/EL
//! tables are compiled in (generated from `archived/go/internal/i18n`).
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
            ("export.show_qr", "Show QR"),
            ("export.qr_title", "TOTP QR code"),
            (
                "export.qr_hint",
                "Scan with your phone camera. Anyone who sees this image can copy the secret.",
            ),
            ("btn.backup", "Backup vault"),
            ("backup.title", "Backup encrypted vault"),
            (
                "backup.msg",
                "Copies the encrypted vault file as-is. The backup needs the same master password.",
            ),
            ("backup.dest", "Destination path"),
            ("status.backup_ok", "Vault backed up • %s"),
            (
                "pw.strength",
                "Password strength: %d/4 (12+ chars, mixed case, digits, symbols)",
            ),
            ("settings.lock_focus", "Lock when window loses focus"),
            ("settings.copy_select", "Copy code on select (single click)"),
            ("settings.font", "Font size"),
            (
                "status.clock_warn",
                "System clock moved backwards — codes may be wrong until it is fixed",
            ),
            (
                "about.keys",
                "Shortcuts: Enter or Ctrl+C copies the selected code • double-click a card also copies • the star keeps an account on top.",
            ),
            ("pin.tip", "Pin to top"),
            ("pin.pinned", "Pinned to top • %s"),
            ("pin.unpinned", "Unpinned • %s"),
            ("login.caps", "Caps Lock is on"),
            ("main.next", "next %s"),
            ("settings.compact", "Compact rows"),
            ("settings.contrast", "High contrast"),
            ("settings.tray", "Tray icon (close hides to tray)"),
            ("tray.show", "Show"),
            (
                "tray.unavailable",
                "System tray unavailable — running without it",
            ),
            ("main.clear", "Clear"),
            ("main.empty_title", "No accounts yet"),
            (
                "main.empty_hint",
                "Add, import a URI or paste a QR screenshot to get started.",
            ),
            ("main.no_results", "No matches — try another search"),
            ("card.copy_tip", "Copy this code"),
            ("status.clears_in", "clears in %ds"),
            ("settings.security", "Security"),
            ("settings.appearance", "Appearance"),
            ("settings.behavior", "Behavior"),
            ("acct.show_secret", "Show"),
            ("acct.hide_secret", "Hide"),
            ("about.copy_path", "Copy path"),
            (
                "about.keys2",
                "More: / focuses search • Esc clears • Up/Down moves selection • per-card Copy copies directly.",
            ),
            ("acct.preview", "Preview"),
            (
                "acct.live_invalid",
                "Fill all fields with a valid Base32 secret to preview the code.",
            ),
        ],
    ),
    (
        "de",
        &[
            ("settings.theme", "Design"),
            ("theme.system", "System"),
            ("theme.light", "Hell"),
            ("theme.dark", "Dunkel"),
            ("export.show_qr", "QR zeigen"),
            ("export.qr_title", "TOTP-QR-Code"),
            (
                "export.qr_hint",
                "Mit der Handykamera scannen. Jeder mit Sicht auf dieses Bild kann das Geheimnis kopieren.",
            ),
            ("btn.backup", "Tresor sichern"),
            ("backup.title", "Verschlüsselten Tresor sichern"),
            (
                "backup.msg",
                "Kopiert die verschlüsselte Tresordatei. Das Backup braucht dasselbe Masterpasswort.",
            ),
            ("backup.dest", "Zielpfad"),
            ("status.backup_ok", "Tresor gesichert • %s"),
            (
                "pw.strength",
                "Passwortstärke: %d/4 (12+ Zeichen, Groß/Klein, Ziffern, Symbole)",
            ),
            ("settings.lock_focus", "Bei Fokusverlust sperren"),
            ("settings.copy_select", "Code bei Auswahl kopieren (Klick)"),
            ("settings.font", "Schriftgröße"),
            (
                "status.clock_warn",
                "Systemuhr läuft rückwärts — Codes evtl. falsch",
            ),
            (
                "about.keys",
                "Tasten: Enter oder Strg+C kopiert den Code • Doppelklick kopiert • der Stern heftet oben an.",
            ),
            ("pin.tip", "Oben anheften"),
            ("pin.pinned", "Oben angeheftet • %s"),
            ("pin.unpinned", "Nicht mehr angeheftet • %s"),
            ("login.caps", "Feststelltaste ist aktiv"),
            ("main.next", "nächster %s"),
            ("settings.compact", "Kompakte Zeilen"),
            ("settings.contrast", "Hoher Kontrast"),
            ("settings.tray", "Systray-Symbol (Schließen blendet aus)"),
            ("tray.show", "Anzeigen"),
            ("tray.unavailable", "Systray nicht verfügbar — läuft ohne"),
            ("main.clear", "Leeren"),
            ("main.empty_title", "Noch keine Konten"),
            (
                "main.empty_hint",
                "Hinzufügen, URI importieren oder QR-Screenshot einfügen.",
            ),
            ("main.no_results", "Keine Treffer — andere Suche versuchen"),
            ("card.copy_tip", "Diesen Code kopieren"),
            ("status.clears_in", "löscht in %ds"),
            ("settings.security", "Sicherheit"),
            ("settings.appearance", "Darstellung"),
            ("settings.behavior", "Verhalten"),
            ("acct.show_secret", "Zeigen"),
            ("acct.hide_secret", "Ausblenden"),
            ("about.copy_path", "Pfad kopieren"),
            (
                "about.keys2",
                "Mehr: / fokussiert Suche • Esc leert • Hoch/Runter wählt • Copy pro Karte kopiert direkt.",
            ),
            ("acct.preview", "Vorschau"),
            (
                "acct.live_invalid",
                "Alle Felder mit gültigem Base32-Secret ausfüllen, um den Code zu sehen.",
            ),
        ],
    ),
    (
        "el",
        &[
            ("settings.theme", "Θέμα"),
            ("theme.system", "Σύστημα"),
            ("theme.light", "Φωτεινό"),
            ("theme.dark", "Σκοτεινό"),
            ("export.show_qr", "Εμφάνιση QR"),
            ("export.qr_title", "Κωδικός QR TOTP"),
            (
                "export.qr_hint",
                "Σαρώστε με την κάμερα του κινητού. Όποιος δει την εικόνα μπορεί να αντιγράψει το μυστικό.",
            ),
            ("btn.backup", "Αντίγραφο vault"),
            ("backup.title", "Αντίγραφο κρυπτογραφημένου vault"),
            (
                "backup.msg",
                "Αντιγράφει το κρυπτογραφημένο αρχείο ως έχει. Χρειάζεται τον ίδιο κύριο κωδικό.",
            ),
            ("backup.dest", "Διαδρομή προορισμού"),
            ("status.backup_ok", "Το vault αντιγράφηκε • %s"),
            (
                "pw.strength",
                "Ισχύς κωδικού: %d/4 (12+ χαρακτήρες, πεζά/κεφαλαία, ψηφία, σύμβολα)",
            ),
            ("settings.lock_focus", "Κλείδωμα όταν χάνεται η εστίαση"),
            (
                "settings.copy_select",
                "Αντιγραφή κωδικού με επιλογή (απλό κλικ)",
            ),
            ("settings.font", "Μέγεθος γραμματοσειράς"),
            (
                "status.clock_warn",
                "Το ρολόι γύρισε πίσω — οι κωδικοί μπορεί να είναι λάθος",
            ),
            (
                "about.keys",
                "Συντομεύσεις: Enter ή Ctrl+C αντιγράφει • διπλό κλικ αντιγράφει • το αστεράκι κρατάει τον λογαριασμό πάνω.",
            ),
            ("pin.tip", "Καρφίτσωμα πάνω"),
            ("pin.pinned", "Καρφιτσωμένο πάνω • %s"),
            ("pin.unpinned", "Ξεκαρφιτσωμένο • %s"),
            ("login.caps", "Το Caps Lock είναι ενεργό"),
            ("main.next", "επόμενος %s"),
            ("settings.compact", "Συμπαγείς γραμμές"),
            ("settings.contrast", "Υψηλή αντίθεση"),
            ("settings.tray", "Εικονίδιο δίσκου (το κλείσιμο κρύβει)"),
            ("tray.show", "Εμφάνιση"),
            (
                "tray.unavailable",
                "Ο δίσκος συστήματος δεν είναι διαθέσιμος",
            ),
            ("main.clear", "Καθαρισμός"),
            ("main.empty_title", "Δεν υπάρχουν λογαριασμοί"),
            (
                "main.empty_hint",
                "Προσθέστε, εισαγάγετε URI ή επικολλήστε QR για να ξεκινήσετε.",
            ),
            ("main.no_results", "Καμία αντιστοίχιση — δοκιμάστε άλλη αναζήτηση"),
            ("card.copy_tip", "Αντιγραφή κωδικού"),
            ("status.clears_in", "καθαρισμός σε %ds"),
            ("settings.security", "Ασφάλεια"),
            ("settings.appearance", "Εμφάνιση"),
            ("settings.behavior", "Συμπεριφορά"),
            ("acct.show_secret", "Εμφάνιση"),
            ("acct.hide_secret", "Απόκρυψη"),
            ("about.copy_path", "Αντιγραφή διαδρομής"),
            (
                "about.keys2",
                "Επιπλέον: / εστίαση αναζήτησης • Esc καθαρισμός • Πάνω/Κάτω επιλογή • Copy ανά κάρτα.",
            ),
            ("acct.preview", "Προεπισκόπηση"),
            (
                "acct.live_invalid",
                "Συμπληρώστε όλα τα πεδία με έγκυρο Base32 μυστικό για προεπισκόπηση.",
            ),
        ],
    ),
    (
        "es",
        &[
            ("settings.theme", "Tema"),
            ("theme.system", "Sistema"),
            ("theme.light", "Claro"),
            ("theme.dark", "Oscuro"),
            ("export.show_qr", "Mostrar QR"),
            ("export.qr_title", "Código QR TOTP"),
            (
                "export.qr_hint",
                "Escanea con la cámara del móvil. Quien vea esta imagen puede copiar el secreto.",
            ),
            ("btn.backup", "Respaldar caja"),
            ("backup.title", "Respaldar caja cifrada"),
            (
                "backup.msg",
                "Copia el archivo cifrado tal cual. Necesita la misma contraseña maestra.",
            ),
            ("backup.dest", "Ruta de destino"),
            ("status.backup_ok", "Caja respaldada • %s"),
            (
                "pw.strength",
                "Seguridad: %d/4 (12+ caracteres, mayús/minús, dígitos, símbolos)",
            ),
            ("settings.lock_focus", "Bloquear al perder el foco"),
            (
                "settings.copy_select",
                "Copiar código al seleccionar (clic)",
            ),
            ("settings.font", "Tamaño de letra"),
            (
                "status.clock_warn",
                "El reloj retrocedió — los códigos pueden fallar",
            ),
            (
                "about.keys",
                "Atajos: Enter o Ctrl+C copia • doble clic copia • la estrella mantiene arriba.",
            ),
            ("pin.tip", "Fijar arriba"),
            ("pin.pinned", "Fijado arriba • %s"),
            ("pin.unpinned", "Soltado • %s"),
            ("login.caps", "Bloq Mayús activado"),
            ("main.next", "siguiente %s"),
            ("settings.compact", "Filas compactas"),
            ("settings.contrast", "Alto contraste"),
            ("settings.tray", "Icono de bandeja (cerrar oculta)"),
            ("tray.show", "Mostrar"),
            ("tray.unavailable", "Bandeja no disponible — sin icono"),
            ("main.clear", "Limpiar"),
            ("main.empty_title", "Sin cuentas todavía"),
            (
                "main.empty_hint",
                "Añade, importa una URI o pega un QR para empezar.",
            ),
            ("main.no_results", "Sin resultados — prueba otra búsqueda"),
            ("card.copy_tip", "Copiar este código"),
            ("status.clears_in", "se borra en %ds"),
            ("settings.security", "Seguridad"),
            ("settings.appearance", "Apariencia"),
            ("settings.behavior", "Comportamiento"),
            ("acct.show_secret", "Mostrar"),
            ("acct.hide_secret", "Ocultar"),
            ("about.copy_path", "Copiar ruta"),
            (
                "about.keys2",
                "Más: / enfoca buscar • Esc limpia • Arriba/Abajo selecciona • Copiar por tarjeta.",
            ),
            ("acct.preview", "Vista previa"),
            (
                "acct.live_invalid",
                "Completa los campos con un secreto Base32 válido para ver el código.",
            ),
        ],
    ),
    (
        "fr",
        &[
            ("settings.theme", "Thème"),
            ("theme.system", "Système"),
            ("theme.light", "Clair"),
            ("theme.dark", "Sombre"),
            ("export.show_qr", "Afficher le QR"),
            ("export.qr_title", "QR TOTP"),
            (
                "export.qr_hint",
                "Scannez avec l’appareil photo. Quiconque voit cette image peut copier le secret.",
            ),
            ("btn.backup", "Sauvegarder le coffre"),
            ("backup.title", "Sauvegarder le coffre chiffré"),
            (
                "backup.msg",
                "Copie le fichier chiffré tel quel. Même mot de passe maître requis.",
            ),
            ("backup.dest", "Chemin de destination"),
            ("status.backup_ok", "Coffre sauvegardé • %s"),
            (
                "pw.strength",
                "Robustesse : %d/4 (12+ caractères, maj/min, chiffres, symboles)",
            ),
            ("settings.lock_focus", "Verrouiller à la perte du focus"),
            (
                "settings.copy_select",
                "Copier le code à la sélection (clic)",
            ),
            ("settings.font", "Taille de police"),
            (
                "status.clock_warn",
                "Horloge reculée — les codes peuvent être faux",
            ),
            (
                "about.keys",
                "Raccourcis : Entrée ou Ctrl+C copie • double-clic copie • l’étoile maintient en haut.",
            ),
            ("pin.tip", "Épingler en haut"),
            ("pin.pinned", "Épinglé en haut • %s"),
            ("pin.unpinned", "Désépinglé • %s"),
            ("login.caps", "Verr Maj activée"),
            ("main.next", "suivant %s"),
            ("settings.compact", "Lignes compactes"),
            ("settings.contrast", "Contraste élevé"),
            ("settings.tray", "Icône de zone (fermer masque)"),
            ("tray.show", "Afficher"),
            ("tray.unavailable", "Zone indisponible — sans icône"),
            ("main.clear", "Effacer"),
            ("main.empty_title", "Aucun compte"),
            (
                "main.empty_hint",
                "Ajoutez, importez une URI ou collez un QR pour commencer.",
            ),
            ("main.no_results", "Aucun résultat — essayez une autre recherche"),
            ("card.copy_tip", "Copier ce code"),
            ("status.clears_in", "efface dans %ds"),
            ("settings.security", "Sécurité"),
            ("settings.appearance", "Apparence"),
            ("settings.behavior", "Comportement"),
            ("acct.show_secret", "Afficher"),
            ("acct.hide_secret", "Masquer"),
            ("about.copy_path", "Copier le chemin"),
            (
                "about.keys2",
                "Suite : / cherche • Échap efface • Haut/Bas sélectionne • Copie par carte.",
            ),
            ("acct.preview", "Aperçu"),
            (
                "acct.live_invalid",
                "Remplissez les champs avec un secret Base32 valide pour prévisualiser.",
            ),
        ],
    ),
    (
        "it",
        &[
            ("settings.theme", "Tema"),
            ("theme.system", "Sistema"),
            ("theme.light", "Chiaro"),
            ("theme.dark", "Scuro"),
            ("export.show_qr", "Mostra QR"),
            ("export.qr_title", "Codice QR TOTP"),
            (
                "export.qr_hint",
                "Scansiona con la fotocamera. Chi vede questa immagine può copiare il segreto.",
            ),
            ("btn.backup", "Backup cassaforte"),
            ("backup.title", "Backup cassaforte cifrata"),
            (
                "backup.msg",
                "Copia il file cifrato così com’è. Serve la stessa password principale.",
            ),
            ("backup.dest", "Percorso di destinazione"),
            ("status.backup_ok", "Cassaforte salvata • %s"),
            (
                "pw.strength",
                "Robustezza: %d/4 (12+ caratteri, maiusc/minusc, cifre, simboli)",
            ),
            ("settings.lock_focus", "Blocca alla perdita del focus"),
            ("settings.copy_select", "Copia codice alla selezione (clic)"),
            ("settings.font", "Dimensione carattere"),
            (
                "status.clock_warn",
                "Orologio indietro — i codici potrebbero essere errati",
            ),
            (
                "about.keys",
                "Scorciatoie: Invio o Ctrl+C copia • doppio clic copia • la stella tiene in alto.",
            ),
            ("pin.tip", "Fissa in alto"),
            ("pin.pinned", "Fissato in alto • %s"),
            ("pin.unpinned", "Non più in alto • %s"),
            ("login.caps", "Blocco maiuscole attivo"),
            ("main.next", "prossimo %s"),
            ("settings.compact", "Righe compatte"),
            ("settings.contrast", "Alto contrasto"),
            ("settings.tray", "Icona vassoio (chiudi nasconde)"),
            ("tray.show", "Mostra"),
            ("tray.unavailable", "Vassoio non disponibile — senza icona"),
            ("main.clear", "Cancella"),
            ("main.empty_title", "Nessun account"),
            (
                "main.empty_hint",
                "Aggiungi, importa un URI o incolla un QR per iniziare.",
            ),
            ("main.no_results", "Nessuna corrispondenza — prova un'altra ricerca"),
            ("card.copy_tip", "Copia questo codice"),
            ("status.clears_in", "cancella tra %ds"),
            ("settings.security", "Sicurezza"),
            ("settings.appearance", "Aspetto"),
            ("settings.behavior", "Comportamento"),
            ("acct.show_secret", "Mostra"),
            ("acct.hide_secret", "Nascondi"),
            ("about.copy_path", "Copia percorso"),
            (
                "about.keys2",
                "Altro: / cerca • Esc pulisce • Su/Giù seleziona • Copia per scheda.",
            ),
            ("acct.preview", "Anteprima"),
            (
                "acct.live_invalid",
                "Compila i campi con un segreto Base32 valido per vedere il codice.",
            ),
        ],
    ),
    (
        "zh",
        &[
            ("settings.theme", "主题"),
            ("theme.system", "跟随系统"),
            ("theme.light", "浅色"),
            ("theme.dark", "深色"),
            ("export.show_qr", "显示二维码"),
            ("export.qr_title", "TOTP 二维码"),
            (
                "export.qr_hint",
                "用手机相机扫描。看到此图像的人均可复制该密钥。",
            ),
            ("btn.backup", "备份保险库"),
            ("backup.title", "备份加密保险库"),
            ("backup.msg", "按原样复制加密文件。备份需要相同的主密码。"),
            ("backup.dest", "目标路径"),
            ("status.backup_ok", "已备份保险库 • %s"),
            (
                "pw.strength",
                "密码强度：%d/4（12+字符、大小写、数字、符号）",
            ),
            ("settings.lock_focus", "窗口失去焦点时锁定"),
            ("settings.copy_select", "选中即复制代码（单击）"),
            ("settings.font", "字体大小"),
            ("status.clock_warn", "系统时钟回拨——代码可能错误"),
            (
                "about.keys",
                "快捷键：Enter 或 Ctrl+C 复制 • 双击复制 • 星标可置顶。",
            ),
            ("pin.tip", "置顶"),
            ("pin.pinned", "已置顶 • %s"),
            ("pin.unpinned", "已取消置顶 • %s"),
            ("login.caps", "大写锁定已开启"),
            ("main.next", "下一个 %s"),
            ("settings.compact", "紧凑行"),
            ("settings.contrast", "高对比度"),
            ("settings.tray", "托盘图标（关闭则隐藏）"),
            ("tray.show", "显示"),
            ("tray.unavailable", "系统托盘不可用——无托盘运行"),
            ("main.clear", "清除"),
            ("main.empty_title", "暂无账户"),
            ("main.empty_hint", "添加、导入 URI 或粘贴二维码开始。"),
            ("main.no_results", "无匹配结果——换个搜索词试试"),
            ("card.copy_tip", "复制此代码"),
            ("status.clears_in", "%ds后清除"),
            ("settings.security", "安全"),
            ("settings.appearance", "外观"),
            ("settings.behavior", "行为"),
            ("acct.show_secret", "显示"),
            ("acct.hide_secret", "隐藏"),
            ("about.copy_path", "复制路径"),
            ("about.keys2", "更多：/ 聚焦搜索 • Esc 清除 • 上/下选择 • 按卡复制。"),
            ("acct.preview", "预览"),
            ("acct.live_invalid", "填写有效的 Base32 密钥以预览验证码。"),
        ],
    ),
];
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
    if let Some(rest) = msg.strip_prefix("duplicate ")
        && let Some(param) = rest.strip_suffix(" parameter")
    {
        return Some(("err.uri_dup".to_string(), vec![Arg::Str(param.to_string())]));
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
