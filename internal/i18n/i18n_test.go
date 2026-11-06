package i18n

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// verbs extracts the printf verbs (%s, %d, %q, …) from a template, ignoring %%.
func verbs(s string) []string {
	var out []string
	for i := 0; i < len(s); i++ {
		if s[i] != '%' || i+1 >= len(s) {
			continue
		}
		i++
		if s[i] == '%' {
			continue
		}
		// Skip flags/width/precision (e.g. %0*d, %3A is not a verb here since
		// PathEscape output is data, not template — templates only use s/d/q).
		for i < len(s) && strings.IndexByte("+-# 0123456789.*", s[i]) >= 0 {
			i++
		}
		if i < len(s) {
			out = append(out, "%"+string(s[i]))
		}
	}
	return out
}

func TestSupportedCoversNativeNames(t *testing.T) {
	if len(Supported()) != 7 {
		t.Fatalf("want 7 languages, got %v", Supported())
	}
	for _, tag := range Supported() {
		if NativeName(tag) == "" || NativeName(tag) == DefaultLang && tag != DefaultLang {
			t.Fatalf("missing native name for %q", tag)
		}
	}
	if IndexOf("") != 0 || IndexOf("xx") != 0 || IndexOf("fr") == 0 {
		t.Fatal("bad IndexOf fallback")
	}
}

func TestAllKeysPresent(t *testing.T) {
	for key := range enStrings {
		for _, tag := range Supported() {
			if tag == "en" {
				continue
			}
			s, ok := byTag[tag][key]
			if !ok || strings.TrimSpace(s) == "" {
				t.Fatalf("language %q misses key %q", tag, key)
			}
		}
	}
}

func TestVerbsMatch(t *testing.T) {
	for key, en := range enStrings {
		want := verbs(en)
		for _, tag := range Supported() {
			if tag == "en" {
				continue
			}
			if got := verbs(byTag[tag][key]); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("language %q key %q verbs %v, want %v", tag, key, got, want)
			}
		}
	}
}

func TestFallbacks(t *testing.T) {
	if Get("xx", "btn.save") != "Save" {
		t.Fatal("unknown language should fall back to English")
	}
	if Get("fr", "btn.save") != "Enregistrer" {
		t.Fatal("french save not translated")
	}
	if Get("", "btn.save") != "Save" {
		t.Fatal("empty language should fall back to English")
	}
	if Get("el", "no.such.key") != "no.such.key" {
		t.Fatal("unknown key should return the key")
	}
}

func TestCount(t *testing.T) {
	if Count("en", 1, "status.accounts_one", "status.accounts_other", 1, "p", "5m") != "1 account • p • auto-lock after 5m idle" {
		t.Fatal("en singular")
	}
	if Count("en", 3, "status.accounts_one", "status.accounts_other", 3, "p", "5m") != "3 accounts • p • auto-lock after 5m idle" {
		t.Fatal("en plural")
	}
	// French treats 0 as singular.
	if Count("fr", 0, "status.accounts_one", "status.accounts_other", 0, "p", "5m") != "0 compte • p • verrouillage auto après 5m d’inactivité" {
		t.Fatal("fr zero singular")
	}
	if got := Count("zh", 1, "status.accounts_one", "status.accounts_other", 1, "p", "5m"); !strings.Contains(got, "1 个账户") {
		t.Fatalf("zh singular: %q", got)
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"fr-FR": "fr", "fr_FR.UTF-8": "fr", "EL_gr": "el", "de": "de",
		"zh-CN": "zh", "zh-Hant-TW": "zh", "es-ES@euro": "es", "it_IT": "it",
		"C": "", "C.UTF-8": "", "POSIX": "", "xx": "", "": "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Fatalf("Normalize(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestErrText(t *testing.T) {
	if ErrText("el", nil) != "" {
		t.Fatal("nil error should map to empty")
	}
	if got := ErrText("el", errors.New("wrong master password or damaged vault")); got != "λάθος κύριος κωδικός ή κατεστραμμένο θησαυροφυλάκιο" {
		t.Fatalf("auth el: %q", got)
	}
	if got := ErrText("fr", errors.New("master password is too long")); got != "le mot de passe maître est trop long" {
		t.Fatalf("pw_long fr: %q", got)
	}
	// Wrapped errors translate prefix and inner part.
	if got := ErrText("de", errors.New("invalid account: secret is too long")); got != "ungültiges Konto: Secret ist zu lang" {
		t.Fatalf("wrapped de: %q", got)
	}
	if got := ErrText("es", errors.New("duplicate issuer parameter")); got != "parámetro issuer duplicado" {
		t.Fatalf("dup param es: %q", got)
	}
	if got := ErrText("zh", errors.New("unsupported parameter: lock")); got != "不支持的参数：lock" {
		t.Fatalf("unsupported zh: %q", got)
	}
	// Unknown errors pass through so nothing is ever hidden.
	if got := ErrText("fr", errors.New("some OS error")); got != "some OS error" {
		t.Fatalf("passthrough: %q", got)
	}
	if got := ErrText("xx", errors.New("vault is locked")); got != "vault is locked" {
		t.Fatalf("unknown lang falls back to English: %q", got)
	}
}
