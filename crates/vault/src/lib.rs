//! Encrypted vault: Argon2id + XChaCha20-Poly1305 file format v1.
//!
//! Byte-compatible with `archived/go/internal/vault/vault.go`: same magic, same KDF
//! parameters, same AEAD construction, same limits. A vault written by the Go
//! app unlocks here and vice versa. Fail closed: tampering, truncation and
//! stale writes are rejected, never guessed.

use aead::AeadInOut;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::convert::TryFrom;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use totpvault_totp::{Account, normalize};
use zeroize::{Zeroize, Zeroizing};

pub const HEADER_SIZE: usize = 48;
pub const MAX_FILE_SIZE: usize = 8 << 20;
pub const MAX_ACCOUNTS: usize = 10_000;

const MAGIC: [u8; 8] = *b"TOTPVLT\x01";

/// Errors. User-facing strings stay identical to the Go backend so the i18n
/// display layer (`ErrText`) keeps working unchanged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("use at least 12 characters for the master password")]
    PasswordShort,
    #[error("master password is too long")]
    PasswordLong,
    #[error("wrong master password or damaged vault")]
    Authentication,
    #[error("vault changed on disk; lock and unlock again before saving")]
    Changed,
    #[error("vault is locked")]
    Locked,
    #[error("vault exceeds size limit")]
    TooBig,
    #[error("unsupported or damaged vault format")]
    BadFormat,
    #[error("invalid vault payload")]
    BadPayload,
    #[error("too many accounts")]
    TooMany,
    #[error("invalid account: {0}")]
    BadAccount(String),
    #[error("{0}")]
    Io(String),
}

fn io_err(e: std::io::Error) -> Error {
    Error::Io(e.to_string())
}

/// Argon2id with format-v1 pinned params: t=3, m=64MiB, p=4, key 32 bytes.
/// Params are never read from the file: hostile headers cannot tune KDF work.
fn derive(password: &str, salt: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let params = Params::new(64 * 1024, 3, 4, Some(32)).expect("fixed argon2 params");
    let ctx = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    ctx.hash_password_into(password.as_bytes(), salt, &mut key[..])
        .expect("argon2id");
    key
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Payload {
    #[serde(default)]
    accounts: Vec<Account>,
}

#[derive(Debug)]
pub struct Session {
    path: PathBuf,
    key: Option<Zeroizing<[u8; 32]>>,
    salt: [u8; 16],
    accounts: Vec<Account>,
    fingerprint: [u8; 32],
}

pub fn check_password(password: &str) -> Result<(), Error> {
    if password.chars().count() < 12 {
        return Err(Error::PasswordShort);
    }
    if password.len() > 1024 {
        return Err(Error::PasswordLong);
    }
    Ok(())
}

fn normalize_all(accounts: Vec<Account>) -> Result<Vec<Account>, Error> {
    if accounts.len() > MAX_ACCOUNTS {
        return Err(Error::TooMany);
    }
    accounts
        .into_iter()
        .map(|a| normalize(a).map_err(|e| Error::BadAccount(e.0)))
        .collect()
}

fn read_limited(path: &Path) -> Result<Vec<u8>, Error> {
    let f = File::open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::Changed
        } else {
            io_err(e)
        }
    })?;
    let mut b = Vec::new();
    f.take((MAX_FILE_SIZE + 1) as u64)
        .read_to_end(&mut b)
        .map_err(io_err)?;
    if b.len() > MAX_FILE_SIZE {
        return Err(Error::TooBig);
    }
    Ok(b)
}

fn write_sync(mut f: &File, b: &[u8]) -> Result<(), Error> {
    f.write_all(b).map_err(io_err)?;
    f.sync_all().map_err(io_err)?;
    Ok(())
}

fn ensure_parent_dir(path: &Path) -> Result<(), Error> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            fs::create_dir_all(dir).map_err(io_err)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
            }
        }
    }
    Ok(())
}

fn encrypt_with(key: &[u8; 32], salt: &[u8; 16], accounts: &[Account]) -> Result<Vec<u8>, Error> {
    let mut plain = Zeroizing::new(
        serde_json::to_vec(&Payload {
            accounts: accounts.to_vec(),
        })
        .map_err(|_| Error::BadPayload)?,
    );
    let mut header = [0u8; HEADER_SIZE];
    header[..8].copy_from_slice(&MAGIC);
    header[8..24].copy_from_slice(salt);
    rand::thread_rng().fill_bytes(&mut header[24..48]);
    if header.len() + plain.len() + 16 > MAX_FILE_SIZE {
        return Err(Error::TooBig);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Authentication)?;
    let nonce = XNonce::try_from(&header[24..48]).map_err(|_| Error::Authentication)?;
    let mut body = plain.to_vec();
    cipher
        .encrypt_in_place(&nonce, &header, &mut body)
        .map_err(|_| Error::Authentication)?;
    plain.zeroize();
    let mut buf = header.to_vec();
    buf.extend_from_slice(&body);
    if buf.len() > MAX_FILE_SIZE {
        return Err(Error::TooBig);
    }
    Ok(buf)
}

fn decrypt(key: &[u8; 32], b: &[u8]) -> Result<Vec<Account>, Error> {
    if b.len() < HEADER_SIZE + 16 || b[..8] != MAGIC {
        return Err(Error::BadFormat);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Authentication)?;
    let nonce = XNonce::try_from(&b[24..48]).map_err(|_| Error::Authentication)?;
    let mut body = b[HEADER_SIZE..].to_vec();
    cipher
        .decrypt_in_place(&nonce, &b[..HEADER_SIZE], &mut body)
        .map_err(|_| Error::Authentication)?;
    let payload: Payload = serde_json::from_slice(&body).map_err(|_| Error::BadPayload)?;
    body.zeroize();
    normalize_all(payload.accounts)
}

impl Session {
    fn fingerprint_of(b: &[u8]) -> [u8; 32] {
        Sha256::digest(b).into()
    }

    pub fn create(path: &Path, password: &str) -> Result<Session, Error> {
        check_password(password)?;
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = derive(password, &salt);
        let data = encrypt_with(&key, &salt, &[])?;
        ensure_parent_dir(path)?;
        let f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::Io("file exists".to_string())
                } else {
                    io_err(e)
                }
            })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
        }
        if let Err(e) = write_sync(&f, &data) {
            drop(f);
            let _ = fs::remove_file(path);
            return Err(e);
        }
        drop(f);
        Ok(Session {
            path: path.to_path_buf(),
            key: Some(key),
            salt,
            accounts: Vec::new(),
            fingerprint: Self::fingerprint_of(&data),
        })
    }

    pub fn unlock(path: &Path, password: &str) -> Result<Session, Error> {
        if password.len() > 1024 {
            return Err(Error::PasswordLong);
        }
        let b = read_limited(path)?;
        if b.len() < HEADER_SIZE + 16 || b[..8] != MAGIC {
            return Err(Error::BadFormat);
        }
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&b[8..24]);
        let key = derive(password, &salt);
        match decrypt(&key, &b) {
            Ok(accounts) => Ok(Session {
                path: path.to_path_buf(),
                key: Some(key),
                salt,
                accounts,
                fingerprint: Self::fingerprint_of(&b),
            }),
            Err(e) => Err(match e {
                Error::BadPayload | Error::BadAccount(_) | Error::BadFormat | Error::TooMany => e,
                _ => Error::Authentication,
            }),
        }
    }

    pub fn accounts(&self) -> Vec<Account> {
        self.accounts.clone()
    }

    pub fn is_locked(&self) -> bool {
        self.key.is_none()
    }

    pub fn lock(&mut self) {
        self.key = None;
        for a in &mut self.accounts {
            *a = Account {
                name: String::new(),
                issuer: String::new(),
                secret: String::new(),
                digits: 0,
                period: 0,
                algorithm: String::new(),
            };
        }
        self.accounts.clear();
    }

    fn encrypt(&self, accounts: &[Account]) -> Result<Vec<u8>, Error> {
        match &self.key {
            Some(k) => encrypt_with(k, &self.salt, accounts),
            None => Err(Error::Locked),
        }
    }

    fn replace(&mut self, b: &[u8]) -> Result<(), Error> {
        let old = File::open(&self.path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::Changed
            } else {
                io_err(e)
            }
        })?;
        let mut old_bytes = Vec::new();
        std::io::BufReader::new(old)
            .take((MAX_FILE_SIZE + 1) as u64)
            .read_to_end(&mut old_bytes)
            .map_err(io_err)?;
        if Self::fingerprint_of(&old_bytes) != self.fingerprint {
            return Err(Error::Changed);
        }
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let mut rnd = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut rnd);
        let tmp = parent.join(format!(
            ".totpvault-{}",
            rnd.iter().map(|x| format!("{:02x}", x)).collect::<String>()
        ));
        let tmpf = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(io_err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = tmpf.set_permissions(fs::Permissions::from_mode(0o600));
        }
        let res = write_sync(&tmpf, b);
        drop(tmpf);
        if let Err(e) = res {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = fs::rename(&tmp, &self.path) {
            let _ = fs::remove_file(&tmp);
            return Err(io_err(e));
        }
        self.fingerprint = Self::fingerprint_of(b);
        if let Ok(dir) = File::open(&parent) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    pub fn save(&mut self, accounts: Vec<Account>) -> Result<(), Error> {
        let accounts = normalize_all(accounts)?;
        let b = self.encrypt(&accounts)?;
        self.replace(&b)?;
        self.accounts = accounts;
        Ok(())
    }

    pub fn change_password(&mut self, password: &str) -> Result<(), Error> {
        if self.key.is_none() {
            return Err(Error::Locked);
        }
        check_password(password)?;
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        let key = derive(password, &salt);
        let b = encrypt_with(&key, &salt, &self.accounts)?;
        self.replace(&b)?;
        self.key = Some(key);
        self.salt = salt;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const PW: &str = "a sufficiently long test password";

    fn tmp() -> PathBuf {
        let mut p = std::env::temp_dir();
        let mut rnd = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut rnd);
        p.push(format!(
            "totpvault-test-{}",
            rnd.iter().map(|x| format!("{:02x}", x)).collect::<String>()
        ));
        let _ = fs::create_dir_all(&p);
        p.join("vault.dat")
    }

    fn sample() -> Account {
        Account {
            name: "private account".into(),
            issuer: "private issuer".into(),
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            digits: 6,
            period: 30,
            algorithm: "SHA1".into(),
        }
    }

    #[test]
    fn lifecycle() {
        let path = tmp();
        let mut s = Session::create(&path, PW).unwrap();
        let a = sample();
        s.save(vec![a.clone()]).unwrap();
        let b = fs::read(&path).unwrap();
        for secret in [PW, &a.name, &a.issuer, &a.secret] {
            assert!(
                !b.windows(secret.len()).any(|w| w == secret.as_bytes()),
                "plaintext leaked"
            );
        }
        assert!(matches!(Session::create(&path, PW), Err(Error::Io(_))));
        assert_eq!(
            Session::unlock(&path, "wrong password").unwrap_err(),
            Error::Authentication
        );
        s.lock();
        assert_eq!(s.save(vec![]).unwrap_err(), Error::Locked);
        let mut s = Session::unlock(&path, PW).unwrap();
        assert_eq!(s.accounts(), vec![a.clone()]);
        let mut copy = s.accounts();
        copy[0].name = "changed".into();
        assert_eq!(s.accounts()[0].name, a.name);
        s.change_password("new sufficiently long password").unwrap();
        assert_eq!(
            Session::unlock(&path, PW).unwrap_err(),
            Error::Authentication
        );
        let mut next = Session::unlock(&path, "new sufficiently long password").unwrap();
        assert_eq!(next.accounts().len(), 1);
        next.save(vec![]).unwrap();
        assert_eq!(s.save(vec![a]).unwrap_err(), Error::Changed);
    }

    #[test]
    fn tampering() {
        let path = tmp();
        let mut s = Session::create(&path, PW).unwrap();
        s.lock();
        let original = fs::read(&path).unwrap();
        for offset in [8usize, 24, 48, original.len() - 1] {
            let mut b = original.clone();
            b[offset] ^= 1;
            fs::write(&path, &b).unwrap();
            assert!(
                Session::unlock(&path, PW).is_err(),
                "tampering at {offset} authenticated"
            );
        }
        for size in [0usize, 7, 47, 48, 63] {
            fs::write(&path, &original[..size]).unwrap();
            assert!(
                Session::unlock(&path, PW).is_err(),
                "accepted truncated {size}"
            );
        }
    }

    #[test]
    fn nonce_and_failed_save() {
        let path = tmp();
        let mut s = Session::create(&path, PW).unwrap();
        let before = fs::read(&path).unwrap();
        s.save(vec![]).unwrap();
        let after = fs::read(&path).unwrap();
        assert_ne!(&before[24..48], &after[24..48], "nonce reused");
        assert!(
            s.save(vec![Account {
                name: "bad".into(),
                issuer: String::new(),
                secret: "not base32".into(),
                digits: 0,
                period: 0,
                algorithm: String::new(),
            }])
            .is_err()
        );
        let still = fs::read(&path).unwrap();
        assert_eq!(after, still, "failed save changed disk");
    }

    #[test]
    fn limits_and_passwords() {
        assert_eq!(check_password("short").unwrap_err(), Error::PasswordShort);
        assert!(check_password(&"a".repeat(11)).is_err());
        assert!(check_password("123456789012").is_ok());
        assert_eq!(
            check_password(&"x".repeat(1025)).unwrap_err(),
            Error::PasswordLong
        );
        let path = tmp();
        let mut s = Session::create(&path, PW).unwrap();
        assert_eq!(
            Session::unlock(&path, &"y".repeat(1025)).unwrap_err(),
            Error::PasswordLong
        );
        assert!(s.change_password("short").is_err());
        let many = vec![
            Account {
                name: "a".into(),
                issuer: String::new(),
                secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
                digits: 0,
                period: 0,
                algorithm: String::new(),
            };
            10001
        ];
        assert!(s.save(many).is_err());
        let big = tmp().with_file_name("big.dat");
        fs::write(&big, vec![0u8; (8 << 20) + 1]).unwrap();
        assert!(Session::unlock(&big, PW).is_err());
        let gone = tmp().with_file_name("gone.dat");
        let mut g = Session::create(&gone, PW).unwrap();
        fs::remove_file(&gone).unwrap();
        assert_eq!(g.save(vec![]).unwrap_err(), Error::Changed);
        s.lock();
        s.lock();
        assert_eq!(s.save(vec![]).unwrap_err(), Error::Locked);
    }

    #[test]
    fn go_interop_fixture() {
        // Fixture written by the archived Go app (see interop/): proves the
        // Rust code reads Go-produced vault bytes with identical KDF/AEAD.
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../interop");
        let path = dir.join("go-vault.dat");
        if !path.exists() {
            return;
        }
        let s = Session::unlock(&path, "interop-test-password-012").unwrap();
        let accs = s.accounts();
        assert_eq!(accs.len(), 2);
        assert_eq!(accs[0].name, "alice@example.com");
        assert_eq!(accs[1].issuer, "Example");
    }
}
