// Writes rust/interop/rust-vault.dat with the Rust vault code so the Go
// side can prove it reads Rust-produced bytes.
use std::path::PathBuf;
use totpvault_totp::Account;

fn main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../interop");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("rust-vault.dat");
    let _ = std::fs::remove_file(&path);
    let mut s = totpvault_vault::Session::create(&path, "interop-test-password-012").unwrap();
    s.save(vec![
        Account {
            name: "carol@example.com".into(),
            issuer: "Rustacean".into(),
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            digits: 6,
            period: 30,
            algorithm: "SHA1".into(),
        },
        Account {
            name: "dave".into(),
            issuer: "Ferris".into(),
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
            digits: 8,
            period: 60,
            algorithm: "SHA256".into(),
        },
    ])
    .unwrap();
    println!("rust fixture ok at {}", path.display());
}
