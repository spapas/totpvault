//! TOTP core (RFC 6238): account validation, code generation and
//! `otpauth://totp/...` URI handling. Pure logic, no I/O, no clock source
//! beyond the Unix timestamp passed in.
//!
//! Fail-closed port of `archived/go/internal/totp/totp.go`: unknown params, HOTP,
//! userinfo, fragments and bad Base32 are rejected, never guessed.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

/// A single TOTP account. JSON-serializable, also the vault payload unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub issuer: String,
    pub secret: String,
    pub digits: u32,
    pub period: i64,
    pub algorithm: String,
}

/// Validation / format error. Messages stay in English: the UI translates at
/// the display boundary, mirroring the Go `i18n.ErrText` design.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn err(msg: &str) -> Error {
    Error(msg.to_string())
}

/// Canonicalize then validate an account (mirrors Go `Normalize`).
pub fn normalize(mut a: Account) -> Result<Account, Error> {
    a.name = a.name.trim().to_string();
    a.issuer = a.issuer.trim().to_string();
    let no_ws: String = a.secret.split_whitespace().collect();
    a.secret = no_ws.to_uppercase();
    while a.secret.ends_with('=') {
        a.secret.pop();
    }
    a.algorithm = a.algorithm.trim().to_uppercase();
    if a.algorithm.is_empty() {
        a.algorithm = "SHA1".to_string();
    }
    if a.digits == 0 {
        a.digits = 6;
    }
    if a.period == 0 {
        a.period = 30;
    }
    if a.name.is_empty() || a.name.len() > 256 || a.issuer.len() > 256 {
        return Err(err("account name is required (maximum 256 bytes)"));
    }
    if a.digits != 6 && a.digits != 8 {
        return Err(err("digits must be 6 or 8"));
    }
    if !(1..=300).contains(&a.period) {
        return Err(err("period must be between 1 and 300 seconds"));
    }
    if a.algorithm != "SHA1" && a.algorithm != "SHA256" && a.algorithm != "SHA512" {
        return Err(err("algorithm must be SHA1, SHA256 or SHA512"));
    }
    if a.secret.len() > 1024 {
        return Err(err("secret is too long"));
    }
    match BASE32_NOPAD.decode(a.secret.as_bytes()) {
        Ok(key) => {
            let len_ok = key.len() >= 10;
            drop(key);
            if !len_ok {
                return Err(err(
                    "secret must be valid Base32 containing at least 10 bytes",
                ));
            }
        }
        Err(_) => {
            return Err(err(
                "secret must be valid Base32 containing at least 10 bytes",
            ));
        }
    }
    Ok(a)
}

/// Compute the current code. Returns `(code, seconds_remaining)`.
/// `unix` is seconds since the Unix epoch; negative values are rejected.
pub fn code(a: &Account, unix: i64) -> Result<(String, i64), Error> {
    let a = normalize(a.clone())?;
    if unix < 0 {
        return Err(err("clock is before the Unix epoch"));
    }
    let key = Zeroizing::new(
        BASE32_NOPAD
            .decode(a.secret.as_bytes())
            .map_err(|_| err("secret must be valid Base32 containing at least 10 bytes"))?,
    );
    let counter = (unix / a.period) as u64;
    let msg = counter.to_be_bytes();
    let digest: Vec<u8> = match a.algorithm.as_str() {
        "SHA256" => {
            let mut mac = Hmac::<Sha256>::new_from_slice(&key)
                .map_err(|_| err("secret must be valid Base32 containing at least 10 bytes"))?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        "SHA512" => {
            let mut mac = Hmac::<Sha512>::new_from_slice(&key)
                .map_err(|_| err("secret must be valid Base32 containing at least 10 bytes"))?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        _ => {
            let mut mac = Hmac::<Sha1>::new_from_slice(&key)
                .map_err(|_| err("secret must be valid Base32 containing at least 10 bytes"))?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
    };
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let number = u32::from_be_bytes([
        digest[offset],
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]) & 0x7fff_ffff;
    let modulus: u32 = if a.digits == 8 {
        100_000_000
    } else {
        1_000_000
    };
    let remaining = a.period - (unix % a.period);
    Ok((
        format!("{:0>width$}", number % modulus, width = a.digits as usize),
        remaining,
    ))
}

/// Percent-encode one label side like Go `escapeLabelPart` (PathEscape with
/// `:` forced to `%3A`). Keeps unreserved + `$&'()*+=@!` (sub-delims the Go
/// path escaper leaves alone); everything else becomes uppercase `%XX`.
fn escape_label_part(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'!'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b'='
            | b'@' => out.push(b as char),
            _ => {
                out.push('%');
                out.push(
                    char::from_digit((b >> 4) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit((b & 0x0f) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

/// Query-escape like Go `url.QueryEscape`: keeps `[A-Za-z0-9-_.~]`,
/// space becomes `+`, everything else uppercase `%XX`.
fn escape_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(
                    char::from_digit((b >> 4) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
                out.push(
                    char::from_digit((b & 0x0f) as u32, 16)
                        .unwrap()
                        .to_ascii_uppercase(),
                );
            }
        }
    }
    out
}

/// Format one account as an `otpauth://totp/...` URI (mirrors Go
/// `ProvisioningURI`: sorted query keys, encoded label).
pub fn provisioning_uri(a: &Account) -> Result<String, Error> {
    let a = normalize(a.clone())?;
    let (label, escaped_label) = if a.issuer.is_empty() {
        (a.name.clone(), escape_label_part(&a.name))
    } else {
        (
            format!("{}:{}", a.issuer, a.name),
            format!(
                "{}:{}",
                escape_label_part(&a.issuer),
                escape_label_part(&a.name)
            ),
        )
    };
    let _ = label;
    let mut q = format!(
        "algorithm={}&digits={}&period={}&secret={}",
        escape_query(&a.algorithm),
        a.digits,
        a.period,
        escape_query(&a.secret),
    );
    if !a.issuer.is_empty() {
        q = format!(
            "algorithm={}&digits={}&issuer={}&period={}&secret={}",
            escape_query(&a.algorithm),
            a.digits,
            escape_query(&a.issuer),
            a.period,
            escape_query(&a.secret)
        );
    } else if a.name.contains(':') {
        q = format!(
            "algorithm={}&digits={}&issuer=&period={}&secret={}",
            escape_query(&a.algorithm),
            a.digits,
            a.period,
            escape_query(&a.secret)
        );
    }
    Ok(format!("otpauth://totp/{}?{}", escaped_label, q))
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode `%XX` sequences; `plus_as_space` mirrors Go QueryUnescape vs
/// PathUnescape behaviour.
fn percent_decode(s: &str, plus_as_space: bool) -> Result<Vec<u8>, ()> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                if i + 2 >= b.len() {
                    return Err(());
                }
                let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) else {
                    return Err(());
                };
                out.push(h << 4 | l);
                i += 3;
            }
            b'+' if plus_as_space => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// Parse `otpauth://totp/...` URIs only. HOTP, userinfo, fragments,
/// duplicate or unknown query keys fail closed (mirrors Go `ParseURI`).
pub fn parse_uri(raw: &str) -> Result<Account, Error> {
    if raw.len() > 8192 {
        return Err(err("URI is too long"));
    }
    let raw = raw.trim();
    let rest = raw
        .strip_prefix("otpauth://totp/")
        .ok_or_else(|| err("expected otpauth://totp/... URI"))?;
    // Split path / query. A second '?' stays inside the query value only via
    // Pair parsing; Go's ParseQuery would treat it literally, but a raw '?'
    // inside path or query is never valid for our keys — keep it simple and
    // fail on opaque extras via key validation below.
    let (escaped_label, query) = match rest.find('?') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    if escaped_label.contains('#') || query.contains('#') {
        return Err(err("expected otpauth://totp/... URI"));
    }
    if escaped_label.is_empty() && query.is_empty() {
        // `otpauth://totp/` with nothing: Go parses empty label then fails
        // on missing secret via Normalize; fall through to the same.
    }
    if query.contains(';') {
        return Err(err("invalid URI query"));
    }
    // Query pairs: split on first '=' like Go; pairs without '=' are skipped.
    let mut seen: Vec<(String, String)> = Vec::new();
    if !query.is_empty() {
        for pair in query.split('&') {
            let Some(eq) = pair.find('=') else { continue };
            let (k, v) = (&pair[..eq], &pair[eq + 1..]);
            let kd = percent_decode(k, true).map_err(|_| err("invalid URI query"))?;
            let vd = percent_decode(v, true).map_err(|_| err("invalid URI query"))?;
            let ks = String::from_utf8(kd).map_err(|_| err("invalid URI query"))?;
            let vs = String::from_utf8(vd).map_err(|_| err("invalid URI query"))?;
            seen.push((ks, vs));
        }
    }
    let mut counts = std::collections::HashMap::new();
    for (k, _) in &seen {
        *counts.entry(k.clone()).or_insert(0usize) += 1;
    }
    for (k, n) in &counts {
        if *n != 1 {
            return Err(Error(format!("duplicate {} parameter", k)));
        }
    }
    for (k, _) in &seen {
        match k.as_str() {
            "secret" | "issuer" | "algorithm" | "digits" | "period" => {}
            _ => return Err(Error(format!("unsupported parameter: {}", k))),
        }
    }
    let get = |key: &str| -> String {
        seen.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let has = |key: &str| seen.iter().any(|(k, _)| k == key);

    let label_bytes = percent_decode(escaped_label, false).map_err(|_| err("invalid URI label"))?;
    // Reject a literal '/' introduced by decoding? Go keeps it in the name;
    // harmless either way — keep Go behaviour (part of the name).
    let label = String::from_utf8(label_bytes).map_err(|_| err("invalid URI label"))?;

    let mut a = Account {
        name: label,
        issuer: get("issuer"),
        secret: get("secret"),
        algorithm: get("algorithm"),
        digits: 0,
        period: 0,
    };
    let has_empty_issuer = has("issuer") && a.issuer.is_empty();
    if !has_empty_issuer {
        let eb = escaped_label.as_bytes();
        let mut matched = false;
        let mut found_separator = false;
        let mut i = 0;
        while i < eb.len() {
            let is_colon = eb[i] == b':'
                || (i + 2 < eb.len()
                    && eb[i] == b'%'
                    && eb[i + 1] == b'3'
                    && (eb[i + 2] == b'A' || eb[i + 2] == b'a'));
            if !is_colon {
                i += 1;
                continue;
            }
            found_separator = true;
            let (raw_prefix, name_start) = if eb[i] == b'%' {
                (&escaped_label[..i], i + 3)
            } else {
                (&escaped_label[..i], i + 1)
            };
            let prefix = percent_decode(raw_prefix, false)
                .ok()
                .and_then(|v| String::from_utf8(v).ok());
            let name_part = percent_decode(&escaped_label[name_start..], false)
                .ok()
                .and_then(|v| String::from_utf8(v).ok());
            let (Some(prefix), Some(name_part)) = (prefix, name_part) else {
                return Err(err("invalid URI label"));
            };
            let prefix = prefix.trim().to_string();
            if !a.issuer.is_empty() && a.issuer != prefix {
                i += 1;
                continue;
            }
            a.issuer = prefix;
            a.name = name_part.trim().to_string();
            matched = true;
            break;
        }
        if found_separator && !get("issuer").is_empty() && !matched {
            return Err(err("issuer does not match label"));
        }
    }
    if has("digits") {
        let v: i64 = get("digits").parse().unwrap_or(0);
        if v == 0 {
            return Err(err("invalid digits"));
        }
        a.digits = v as u32;
    }
    if has("period") {
        let v: i64 = get("period").parse().unwrap_or(0);
        if v == 0 {
            return Err(err("invalid period"));
        }
        a.period = v;
    }
    normalize(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE32_NOPAD;

    fn b32(raw: &[u8]) -> String {
        BASE32_NOPAD.encode(raw)
    }

    #[test]
    fn rfc6238_vectors() {
        // RFC 6238 Appendix B, 8-digit codes, period 30.
        let times = [
            59i64,
            1_111_111_109,
            1_111_111_111,
            1_234_567_890,
            2_000_000_000,
            20_000_000_000,
        ];
        let cases = [
            (
                "SHA1",
                "12345678901234567890",
                [
                    "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
                ],
            ),
            (
                "SHA256",
                "12345678901234567890123456789012",
                [
                    "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
                ],
            ),
            (
                "SHA512",
                "1234567890123456789012345678901234567890123456789012345678901234",
                [
                    "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
                ],
            ),
        ];
        for (algo, secret, want) in cases {
            for (i, ts) in times.iter().enumerate() {
                let a = Account {
                    name: "RFC".into(),
                    issuer: String::new(),
                    secret: b32(secret.as_bytes()),
                    digits: 8,
                    period: 30,
                    algorithm: algo.into(),
                };
                let (got, remaining) = code(&a, *ts).unwrap();
                assert_eq!(got, want[i], "{algo} t={ts}");
                assert_eq!(remaining, 30 - (*ts % 30));
            }
        }
    }

    #[test]
    fn boundary_and_rejects() {
        let a = parse_uri("otpauth://totp/GitHub:user%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub").unwrap();
        assert_eq!(a.name, "user@example.com");
        assert_eq!(a.issuer, "GitHub");
        assert_eq!(a.period, 30);
        let (b, r1) = code(&a, 59).unwrap();
        let (c, r2) = code(&a, 60).unwrap();
        assert_ne!(b, c);
        assert_eq!(r1, 1);
        assert_eq!(r2, 30);
        for raw in [
            "otpauth://hotp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "otpauth://totp/test?secret=short",
            "otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=0",
            "otpauth://totp/A:test?issuer=B&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=6&digits=8",
            "otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=MD5",
        ] {
            assert!(parse_uri(raw).is_err(), "accepted {raw}");
        }
    }

    #[test]
    fn provisioning_round_trip() {
        for a in [
            Account {
                name: "user@example.com".into(),
                issuer: "Example: Service".into(),
                secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
                digits: 8,
                period: 60,
                algorithm: "SHA256".into(),
            },
            Account {
                name: "account:with/slash".into(),
                issuer: String::new(),
                secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
                digits: 6,
                period: 30,
                algorithm: "SHA1".into(),
            },
        ] {
            let raw = provisioning_uri(&a).unwrap();
            let got = parse_uri(&raw).unwrap();
            assert_eq!(got, a, "round trip {raw}");
        }
    }

    #[test]
    fn encoded_issuer_separator() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let cases = [
            (
                format!("otpauth://totp/Example%3Aalice?issuer=Example&secret={secret}"),
                "Example",
                "alice",
                false,
            ),
            (
                format!("otpauth://totp/Example%3Aalice?issuer=Other&secret={secret}"),
                "",
                "",
                true,
            ),
            (
                format!("otpauth://totp/Example%3Aalice?secret={secret}"),
                "Example",
                "alice",
                false,
            ),
        ];
        for (raw, wi, wn, want_err) in cases {
            let res = parse_uri(&raw);
            assert_eq!(res.is_err(), want_err, "{raw}");
            if !want_err {
                let got = res.unwrap();
                assert_eq!(got.issuer, wi);
                assert_eq!(got.name, wn);
            }
        }
    }

    #[test]
    fn validation_edges() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        for raw in [
            "otpauth://totp/x".to_string(),
            format!("otpauth://totp/x?secret={secret}&digits=5"),
            format!("otpauth://totp/x?secret={secret}&digits=7"),
            format!("otpauth://totp/x?secret={secret}&period=301"),
            format!("otpauth://totp/x?secret={secret}&period=-1"),
            format!("otpauth://user@totp/x?secret={secret}"),
            format!("otpauth://totp/x?secret={secret}#frag"),
            format!("otpauth://totp/x?secret=!!!!"),
            "otpauth://totp/x?secret=JBSWY3DP".to_string(),
        ] {
            assert!(parse_uri(&raw).is_err(), "accepted {raw}");
        }
        assert!(
            normalize(Account {
                name: "".into(),
                issuer: String::new(),
                secret: secret.into(),
                digits: 0,
                period: 0,
                algorithm: String::new()
            })
            .is_err()
        );
        assert!(
            normalize(Account {
                name: "a".repeat(257),
                issuer: String::new(),
                secret: secret.into(),
                digits: 0,
                period: 0,
                algorithm: String::new()
            })
            .is_err()
        );
        assert!(
            normalize(Account {
                name: "x".into(),
                issuer: String::new(),
                secret: secret.into(),
                digits: 0,
                period: 0,
                algorithm: "sha256".into()
            })
            .is_ok()
        );
        assert!(
            code(
                &Account {
                    name: "x".into(),
                    issuer: String::new(),
                    secret: secret.into(),
                    digits: 0,
                    period: 0,
                    algorithm: String::new()
                },
                -1
            )
            .is_err()
        );
        assert!(
            provisioning_uri(&Account {
                name: "".into(),
                issuer: String::new(),
                secret: secret.into(),
                digits: 0,
                period: 0,
                algorithm: String::new()
            })
            .is_err()
        );
    }
}
