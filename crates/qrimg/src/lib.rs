//! Offline QR decode: image bytes -> text payload.
//!
//! Mirrors `archived/go/internal/qrimg`: PNG/JPEG only, size guards, single symbol.
//! The payload is NOT interpreted here; callers must pass it through
//! `totpvault_totp::parse_uri` so non-TOTP content fails closed.

use std::io::Cursor;

pub const MAX_IMAGE_BYTES: usize = 5 << 20;
pub const MAX_DIMENSION: u32 = 4000;
pub const MAX_PIXELS: u64 = 16_000_000;
pub const MAX_TEXT_LEN: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("image is empty")]
    Empty,
    #[error("image exceeds 5 MiB limit")]
    TooBig,
    #[error("clipboard does not hold a readable PNG/JPEG image")]
    Unreadable,
    #[error("image dimensions out of range")]
    BadDims,
    #[error("image has too many pixels")]
    TooManyPixels,
    #[error("no QR code found in image")]
    NotFound,
    #[error("could not decode QR code")]
    DecodeFailed,
    #[error("QR code holds no text")]
    NoText,
    #[error("QR code content is too long")]
    TooLong,
}

/// Decode PNG/JPEG bytes holding a single QR code into its text.
pub fn decode_bytes(data: &[u8]) -> Result<String, Error> {
    if data.is_empty() {
        return Err(Error::Empty);
    }
    if data.len() > MAX_IMAGE_BYTES {
        return Err(Error::TooBig);
    }
    let reader = image::ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .map_err(|_| Error::Unreadable)?;
    match reader.format() {
        Some(image::ImageFormat::Png) | Some(image::ImageFormat::Jpeg) => {}
        _ => return Err(Error::Unreadable),
    }
    let (w, h) = reader.into_dimensions().map_err(|_| Error::Unreadable)?;
    if w == 0 || h == 0 || w > MAX_DIMENSION || h > MAX_DIMENSION {
        return Err(Error::BadDims);
    }
    if (w as u64) * (h as u64) > MAX_PIXELS {
        return Err(Error::TooManyPixels);
    }
    let img = image::load_from_memory(data).map_err(|_| Error::Unreadable)?;
    let gray = img.to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(gray);
    let grids = prepared.detect_grids();
    if grids.is_empty() {
        return Err(Error::NotFound);
    }
    let (_meta, content) = grids[0].decode().map_err(|_| Error::DecodeFailed)?;
    let text = content.trim().to_string();
    if text.is_empty() {
        return Err(Error::NoText);
    }
    if text.len() > MAX_TEXT_LEN {
        return Err(Error::TooLong);
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Uses only the public RFC 6238 test secret, never real user data.
    const TEST_URI: &str = "otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&digits=6&period=30&algorithm=SHA1";

    fn encode_uri(text: &str) -> Vec<u8> {
        let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
        let img = code.render::<image::Luma<u8>>().build();
        let mut buf = Vec::new();
        let mut cur = Cursor::new(&mut buf);
        img.write_to(&mut cur, image::ImageFormat::Png).unwrap();
        buf
    }

    #[test]
    fn round_trip() {
        let png = encode_uri(TEST_URI);
        let text = decode_bytes(&png).unwrap();
        assert_eq!(text, TEST_URI);
        assert!(totpvault_totp::parse_uri(&text).is_ok());
    }

    #[test]
    fn non_totp_decodes_but_caller_rejects() {
        let png = encode_uri("https://example.com");
        let text = decode_bytes(&png).unwrap();
        assert_eq!(text, "https://example.com");
        assert!(totpvault_totp::parse_uri(&text).is_err());
    }

    fn solid_png(w: u32, h: u32) -> Vec<u8> {
        let img = image::GrayImage::from_pixel(w, h, image::Luma([255u8]));
        let mut buf = Vec::new();
        let mut cur = Cursor::new(&mut buf);
        img.write_to(&mut cur, image::ImageFormat::Png).unwrap();
        buf
    }

    #[test]
    fn rejects() {
        assert_eq!(decode_bytes(&[]).unwrap_err(), Error::Empty);
        assert_eq!(
            decode_bytes(b"not an image").unwrap_err(),
            Error::Unreadable
        );
        assert_eq!(
            decode_bytes(&solid_png(100, 100)).unwrap_err(),
            Error::NotFound
        );
        assert_eq!(
            decode_bytes(&vec![0u8; (5 << 20) + 1]).unwrap_err(),
            Error::TooBig
        );
        // A single QR symbol holds at most ~7089 chars, below the 8192 text
        // guard, so overlong payloads are rejected downstream by
        // totpvault-totp (covered in totp tests). The length check in
        // decode_bytes stays as defense-in-depth.
    }
}
