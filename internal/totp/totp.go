// Package totp implements the time-based OTP defined by RFC 6238.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Account struct {
	Name      string `json:"name"`
	Issuer    string `json:"issuer,omitempty"`
	Secret    string `json:"secret"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
	Algorithm string `json:"algorithm"`
}

func Normalize(a Account) (Account, error) {
	a.Name = strings.TrimSpace(a.Name)
	a.Issuer = strings.TrimSpace(a.Issuer)
	a.Secret = strings.ToUpper(strings.Join(strings.Fields(a.Secret), ""))
	a.Secret = strings.TrimRight(a.Secret, "=")
	a.Algorithm = strings.ToUpper(strings.TrimSpace(a.Algorithm))
	if a.Algorithm == "" {
		a.Algorithm = "SHA1"
	}
	if a.Digits == 0 {
		a.Digits = 6
	}
	if a.Period == 0 {
		a.Period = 30
	}
	if a.Name == "" || len(a.Name) > 256 || len(a.Issuer) > 256 {
		return a, errors.New("account name is required (maximum 256 bytes)")
	}
	if a.Digits != 6 && a.Digits != 8 {
		return a, errors.New("digits must be 6 or 8")
	}
	if a.Period < 1 || a.Period > 300 {
		return a, errors.New("period must be between 1 and 300 seconds")
	}
	if a.Algorithm != "SHA1" && a.Algorithm != "SHA256" && a.Algorithm != "SHA512" {
		return a, errors.New("algorithm must be SHA1, SHA256 or SHA512")
	}
	if len(a.Secret) > 1024 {
		return a, errors.New("secret is too long")
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(a.Secret)
	if err != nil || len(key) < 10 {
		return a, errors.New("secret must be valid Base32 containing at least 10 bytes")
	}
	clear(key)
	return a, nil
}

func Code(a Account, now time.Time) (string, int, error) {
	a, err := Normalize(a)
	if err != nil {
		return "", 0, err
	}
	if now.Unix() < 0 {
		return "", 0, errors.New("clock is before the Unix epoch")
	}
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(a.Secret)
	defer clear(key)
	var h func() hash.Hash
	switch a.Algorithm {
	case "SHA256":
		h = sha256.New
	case "SHA512":
		h = sha512.New
	default:
		h = sha1.New
	}
	mac := hmac.New(h, key)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/int64(a.Period)))
	_, _ = mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	number := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1000000)
	if a.Digits == 8 {
		modulus = 100000000
	}
	return fmt.Sprintf("%0*d", a.Digits, number%modulus), a.Period - int(now.Unix()%int64(a.Period)), nil
}

// ParseURI accepts TOTP provisioning URIs only; HOTP and unknown options fail closed.
func ParseURI(raw string) (Account, error) {
	var a Account
	if len(raw) > 8192 {
		return a, errors.New("URI is too long")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" || u.User != nil || u.Fragment != "" {
		return a, errors.New("expected otpauth://totp/... URI")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return a, errors.New("invalid URI query")
	}
	for k, v := range q {
		if len(v) != 1 {
			return a, fmt.Errorf("duplicate %s parameter", k)
		}
		switch k {
		case "secret", "issuer", "algorithm", "digits", "period":
		default:
			return a, fmt.Errorf("unsupported parameter: %s", k)
		}
	}
	a.Name = strings.TrimPrefix(u.Path, "/")
	a.Issuer = q.Get("issuer")
	if prefix, name, ok := strings.Cut(a.Name, ":"); ok {
		prefix = strings.TrimSpace(prefix)
		if a.Issuer != "" && a.Issuer != prefix {
			return a, errors.New("issuer does not match label")
		}
		a.Issuer, a.Name = prefix, strings.TrimSpace(name)
	}
	a.Secret, a.Algorithm = q.Get("secret"), q.Get("algorithm")
	if q.Has("digits") {
		a.Digits, err = strconv.Atoi(q.Get("digits"))
		if err != nil || a.Digits == 0 {
			return a, errors.New("invalid digits")
		}
	}
	if q.Has("period") {
		a.Period, err = strconv.Atoi(q.Get("period"))
		if err != nil || a.Period == 0 {
			return a, errors.New("invalid period")
		}
	}
	return Normalize(a)
}
