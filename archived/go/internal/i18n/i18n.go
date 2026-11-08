// Package i18n provides offline UI translations for TOTP Vault.
//
// English is the source language: every message ID has an English template
// and per-language overrides for French, German, Italian, Spanish, Chinese
// (Simplified) and Greek. There is no I/O and no network access; all tables
// are compiled in. Backend packages (totp, vault, qrimg) keep returning
// English errors and the UI translates them at the display boundary via
// ErrText, so crypto and validation code stays untouched.
package i18n

import (
	"errors"
	"fmt"
	"os"
	"strings"

	locale "github.com/jeandeaual/go-locale"
)

// DefaultLang is the fallback language tag.
const DefaultLang = "en"

// supported lists language tags in UI order (English first, rest alphabetical).
var supported = []string{"en", "de", "el", "es", "fr", "it", "zh"}

// nativeNames holds the language selector labels in each language itself.
var nativeNames = map[string]string{
	"en": "English",
	"de": "Deutsch",
	"el": "Ελληνικά",
	"es": "Español",
	"fr": "Français",
	"it": "Italiano",
	"zh": "中文",
}

// Supported returns the language tags the UI can display, in selector order.
func Supported() []string { return append([]string(nil), supported...) }

// NativeName returns the selector label for a tag ("fr" -> "Français").
// Unknown tags fall back to English.
func NativeName(tag string) string {
	if n, ok := nativeNames[Normalize(tag)]; ok {
		return n
	}
	return nativeNames[DefaultLang]
}

// IndexOf returns the selector index of a tag, or 0 (English) when unknown.
func IndexOf(tag string) int {
	n := Normalize(tag)
	if n == "" {
		return 0
	}
	for i, t := range supported {
		if t == n {
			return i
		}
	}
	return 0
}

// Normalize maps locale strings such as "fr-FR", "el_GR.UTF-8" or "zh-Hans"
// to a supported tag ("fr", "el", "zh"). It returns "" when the input does
// not map to a supported language.
func Normalize(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "-", "_")
	if i := strings.IndexByte(s, '.'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '@'); i >= 0 {
		s = s[:i]
	}
	if s == "" || s == "c" || s == "posix" {
		return ""
	}
	base := s
	if i := strings.IndexByte(s, '_'); i >= 0 {
		base = s[:i]
	}
	// All Chinese variants fall back to Simplified for v1.
	if base == "zh" {
		return "zh"
	}
	switch base {
	case "en", "fr", "de", "it", "es", "el":
		return base
	}
	return ""
}

// Detect returns the OS language mapped to a supported tag, or "en" when the
// OS language is unknown or unsupported. Detection order: OS locale API
// (works on Windows and Linux), then LANGUAGE/LC_ALL/LC_MESSAGES/LANG.
func Detect() string {
	if s, err := locale.GetLanguage(); err == nil && s != "" {
		if t := Normalize(s); t != "" {
			return t
		}
	}
	for _, k := range []string{"LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" {
			for _, part := range strings.Split(v, ":") {
				if t := Normalize(part); t != "" {
					return t
				}
			}
		}
	}
	return DefaultLang
}

// byTag registers every language table. Tables live in lang_*.go.
var byTag = map[string]map[string]string{
	"en": enStrings,
	"de": deStrings,
	"el": elStrings,
	"es": esStrings,
	"fr": frStrings,
	"it": itStrings,
	"zh": zhStrings,
}

// tag resolves a language input to a known tag, defaulting to English.
func tag(lang string) string {
	if t := Normalize(lang); t != "" {
		return t
	}
	return DefaultLang
}

// Get returns the translated template for key in lang, formatted with args.
// Unknown languages fall back to English; unknown keys return the key itself
// so a missing translation is visible instead of blank.
func Get(lang, key string, args ...any) string {
	t := tag(lang)
	if m, ok := byTag[t]; ok {
		if s, ok := m[key]; ok {
			return format(s, args)
		}
	}
	if s, ok := enStrings[key]; ok {
		return format(s, args)
	}
	return key
}

// Count selects the singular (n==1) or plural template. French treats 0 as
// singular; Chinese uses identical templates. Both templates take the same
// argument list, with the count rendered through %d (e.g. "showing %d of %d").
func Count(lang string, n int, oneKey, otherKey string, args ...any) string {
	t := tag(lang)
	if t == "fr" {
		if n <= 1 {
			return Get(t, oneKey, args...)
		}
		return Get(t, otherKey, args...)
	}
	if n == 1 {
		return Get(t, oneKey, args...)
	}
	return Get(t, otherKey, args...)
}

func format(tmpl string, args []any) string {
	if len(args) == 0 {
		return tmpl
	}
	return fmt.Sprintf(tmpl, args...)
}

// errKeys maps known backend (English) error texts to message IDs so errors
// from totp/vault/qrimg can be shown translated. Anything unmapped passes
// through unchanged, so new errors stay visible instead of blank.
var errKeys = map[string]string{
	"use at least 12 characters for the master password":         "err.pw_short",
	"master password is too long":                                "err.pw_long",
	"wrong master password or damaged vault":                     "err.auth",
	"vault changed on disk; lock and unlock again before saving": "err.changed",
	"vault is locked":                                          "err.locked",
	"vault exceeds size limit":                                 "err.size",
	"unsupported or damaged vault format":                      "err.format",
	"invalid vault payload":                                    "err.payload",
	"too many accounts":                                        "err.many",
	"account name is required (maximum 256 bytes)":             "err.name",
	"digits must be 6 or 8":                                    "err.digits",
	"period must be between 1 and 300 seconds":                 "err.period_range",
	"algorithm must be SHA1, SHA256 or SHA512":                 "err.algo",
	"secret is too long":                                       "err.secret_long",
	"secret must be valid Base32 containing at least 10 bytes": "err.secret_b32",
	"clock is before the Unix epoch":                           "err.epoch",
	"URI is too long":                                          "err.uri_long",
	"expected otpauth://totp/... URI":                          "err.uri_expected",
	"invalid URI query":                                        "err.uri_query",
	"invalid URI label":                                        "err.uri_label",
	"issuer does not match label":                              "err.uri_issuer",
	"invalid digits":                                           "err.uri_digits",
	"invalid period":                                           "err.uri_period",
	"passwords do not match":                                   "settings.err_mismatch",
	"Passwords do not match":                                   "login.mismatch",
	"invalid idle minutes":                                     "settings.err_idle",
	"account changed meanwhile; reopen and try again":          "acct.err_changed",
	"image is empty":                                           "qr.img_empty",
	"image exceeds 5 MiB limit":                                "qr.img_big",
	"clipboard does not hold a readable PNG/JPEG image":        "qr.img_unreadable",
	"image dimensions out of range":                            "qr.img_dims",
	"image has too many pixels":                                "qr.img_pixels",
	"no QR code found in image":                                "qr.not_found",
	"could not decode QR code":                                 "qr.decode_fail",
	"QR code holds no text":                                    "qr.no_text",
	"QR code content is too long":                              "qr.too_long",
}

// errPrefixes handles wrapped errors of the form "<prefix><inner>" where the
// inner part is itself translated recursively.
var errPrefixes = []struct{ prefix, key string }{
	{"invalid account: ", "err.invalid_account"},
	{"QR code is not a valid TOTP URI: ", "qr.invalid"},
	{"clipboard unavailable: ", "qr.clip_unavail"},
}

// ErrText translates backend and UI error values for display. Unknown errors
// keep their original text.
func ErrText(lang string, err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	for _, p := range errPrefixes {
		if rest, ok := strings.CutPrefix(msg, p.prefix); ok {
			return Get(lang, p.key, ErrText(lang, errors.New(rest)))
		}
	}
	// "duplicate <param> parameter" carries the offending parameter name.
	if rest, ok := strings.CutPrefix(msg, "duplicate "); ok {
		if param, ok := strings.CutSuffix(rest, " parameter"); ok {
			return Get(lang, "err.uri_dup", param)
		}
	}
	if rest, ok := strings.CutPrefix(msg, "unsupported parameter: "); ok {
		return Get(lang, "err.uri_unsupported", rest)
	}
	if key, ok := errKeys[msg]; ok {
		return Get(lang, key)
	}
	return msg
}
