import re, pathlib

# Repo root is two levels up from this file (crates/i18n/gen_tables.py).
ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "archived" / "go" / "internal" / "i18n"
OUT = ROOT / "crates" / "i18n" / "src" / "tables.rs"

pair = re.compile(r'"((?:[^"\\]|\\.)*)"\s*:\s+"((?:[^"\\]|\\.)*)",')

langs = ["en", "de", "el", "es", "fr", "it", "zh"]
tables = {}
for lang in langs:
    text = (SRC / f"{lang}.go").read_text(encoding="utf-8")
    pairs = pair.findall(text)
    assert len(pairs) > 80, (lang, len(pairs))
    tables[lang] = pairs

en_keys = [k for k, _ in tables["en"]]
for lang in langs[1:]:
    ks = [k for k, _ in tables[lang]]
    assert sorted(ks) == sorted(en_keys), f"key mismatch in {lang}"

def rust_str(go: str) -> str:
    # Go double-quoted escapes (\\n, \\\", \\\\) are valid Rust escapes too.
    return '"' + go.replace('"', '\\"') if False else '"' + go + '"'

lines = []
lines.append("// AUTO-GENERATED from archived/go/internal/i18n/*.go — do not hand-edit.")
lines.append("// Regenerate: python3 crates/i18n/gen_tables.py")
lines.append("")
for lang in langs:
    lines.append(f"pub static {lang.upper()}: &[(&str, &str)] = &[")
    for k, v in tables[lang]:
        lines.append(f'    ("{k}", "{v}"),')
    lines.append("];")
    lines.append("")

lines.append("pub fn table(lang: &str) -> &'static [(&'static str, &'static str)] {")
lines.append("    match lang {")
for lang in langs:
    lines.append(f'        "{lang}" => {lang.upper()},')
lines.append('        _ => EN,')
lines.append("    }")
lines.append("}")
lines.append("")

OUT.write_text("\n".join(lines), encoding="utf-8")
print("wrote", OUT, "langs:", {l: len(tables[l]) for l in langs})
