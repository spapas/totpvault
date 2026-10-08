package totp

import (
	"encoding/base32"
	"testing"
	"time"
)

func TestRFC6238(t *testing.T) {
	times := []int64{59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000}
	cases := []struct {
		algorithm, secret string
		want              []string
	}{
		{"SHA1", "12345678901234567890", []string{"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"}},
		{"SHA256", "12345678901234567890123456789012", []string{"46119246", "68084774", "67062674", "91819424", "90698825", "77737706"}},
		{"SHA512", "1234567890123456789012345678901234567890123456789012345678901234", []string{"90693936", "25091201", "99943326", "93441116", "38618901", "47863826"}},
	}
	for _, tc := range cases {
		for i, ts := range times {
			a := Account{Name: "RFC", Secret: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(tc.secret)), Digits: 8, Period: 30, Algorithm: tc.algorithm}
			got, remaining, err := Code(a, time.Unix(ts, 0))
			if err != nil || got != tc.want[i] || remaining != 30-int(ts%30) {
				t.Fatalf("%s %d: got %s, remaining %d, err %v", tc.algorithm, ts, got, remaining, err)
			}
		}
	}
}

func TestBoundaryAndURI(t *testing.T) {
	a, err := ParseURI("otpauth://totp/GitHub:user%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub")
	if err != nil || a.Name != "user@example.com" || a.Issuer != "GitHub" || a.Period != 30 {
		t.Fatalf("parse: %+v %v", a, err)
	}
	before, r, _ := Code(a, time.Unix(59, 0))
	after, r2, _ := Code(a, time.Unix(60, 0))
	if before == after || r != 1 || r2 != 30 {
		t.Fatal("incorrect rollover")
	}
	for _, raw := range []string{
		"otpauth://hotp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		"otpauth://totp/test?secret=short",
		"otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=0",
		"otpauth://totp/A:test?issuer=B&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		"otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=6&digits=8",
		"otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=MD5",
	} {
		if _, err := ParseURI(raw); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
