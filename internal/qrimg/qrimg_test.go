package qrimg

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"

	qr "github.com/piglig/go-qr/v2"
	"github.com/spapas/totpvault/internal/totp"
)

// Uses only the public RFC 6238 test secret, never real user data.
const testURI = "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&digits=6&period=30&algorithm=SHA1"

func encodeURI(t *testing.T, text string) []byte {
	t.Helper()
	code, err := qr.Encode(text)
	if err != nil {
		t.Fatal(err)
	}
	pngBytes, err := code.PNG()
	if err != nil {
		t.Fatal(err)
	}
	return pngBytes
}

func TestRoundTrip(t *testing.T) {
	pngBytes := encodeURI(t, testURI)
	text, err := DecodeBytes(pngBytes)
	if err != nil {
		t.Fatal(err)
	}
	if text != testURI {
		t.Fatalf("decoded %q, want %q", text, testURI)
	}
	if _, err = totp.ParseURI(text); err != nil {
		t.Fatalf("decoded QR is not a valid TOTP URI: %v", err)
	}
}

func TestNonTOTPQRDecodesButCallerRejects(t *testing.T) {
	pngBytes := encodeURI(t, "https://example.com")
	text, err := DecodeBytes(pngBytes)
	if err != nil {
		t.Fatal(err)
	}
	if text != "https://example.com" {
		t.Fatalf("decoded %q", text)
	}
	if _, err = totp.ParseURI(text); err == nil {
		t.Fatal("non-TOTP QR content must not parse as TOTP URI")
	}
}

func solidPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.White)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestRejects(t *testing.T) {
	if _, err := DecodeBytes(nil); err == nil {
		t.Error("empty input must fail")
	}
	if _, err := DecodeBytes([]byte("not an image")); err == nil {
		t.Error("non-image bytes must fail")
	}
	if _, err := DecodeBytes(solidPNG(t, 100, 100)); err == nil {
		t.Error("image without QR code must fail")
	}
	big := make([]byte, (5<<20)+1)
	if _, err := DecodeBytes(big); err == nil {
		t.Error("oversize input must fail")
	}
	// Note: a single QR symbol holds at most ~7089 chars, below the 8192
	// text guard, so overlong payloads are rejected downstream by
	// totp.ParseURI (covered in totp tests). The length check in
	// DecodeBytes stays as defense-in-depth.
}
