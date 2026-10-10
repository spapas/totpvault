// Package qrimg decodes a QR image (clipboard/file bytes) into its text
// payload, offline. It does not interpret the payload; callers must pass
// the result through totp.ParseURI so non-TOTP QR content fails closed.
package qrimg

import (
	"bytes"
	"errors"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"strings"

	qr "github.com/piglig/go-qr/v2"
)

const (
	maxImageBytes = 5 << 20
	maxDimension  = 4000
	maxPixels     = 16_000_000
	// Mirrors totp.ParseURI's limit so oversized payloads fail early.
	maxTextLen = 8192
)

// DecodeBytes reads PNG/JPEG bytes holding a single QR code and returns its
// text. Screenshots, photos and inverted codes are handled by the decoder;
// images without a QR code, with unreadable symbols, or outside size limits
// return an error.
func DecodeBytes(data []byte) (string, error) {
	if len(data) == 0 {
		return "", errors.New("image is empty")
	}
	if len(data) > maxImageBytes {
		return "", errors.New("image exceeds 5 MiB limit")
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return "", errors.New("clipboard does not hold a readable PNG/JPEG image")
	}
	b := img.Bounds()
	dx, dy := b.Dx(), b.Dy()
	if dx <= 0 || dy <= 0 || dx > maxDimension || dy > maxDimension {
		return "", errors.New("image dimensions out of range")
	}
	if int64(dx)*int64(dy) > maxPixels {
		return "", errors.New("image has too many pixels")
	}
	res, err := qr.Decode(img)
	if err != nil {
		if errors.Is(err, qr.ErrNotFound) {
			return "", errors.New("no QR code found in image")
		}
		return "", errors.New("could not decode QR code")
	}
	text := strings.TrimSpace(res.Text)
	if text == "" {
		return "", errors.New("QR code holds no text")
	}
	if len(text) > maxTextLen {
		return "", errors.New("QR code content is too long")
	}
	return text, nil
}
