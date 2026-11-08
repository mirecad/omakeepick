//! Opening real KDBX files. The fixtures were written by KeePassXC (`tests/fixtures/make.sh`);
//! the Argon2/ChaCha20 KDBX 4 variants are re-encrypted on the fly.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use keepass::config::{DatabaseVersion, InnerCipherConfig, KdfConfig, OuterCipherConfig};
use keepass::{Database, DatabaseKey};
use omakeepickd::autotype::{self, Fields, Token};
use omakeepickd::opener::Opener;
use omakeepickd::totp;
use omakeepickd::vault::{self, KeyMaterial, OpenDb, VaultError};
use zeroize::Zeroizing;

const BIN: &str = env!("CARGO_BIN_EXE_omakeepickd");
const PASSWORD: &str = "test-password";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}

fn key(password: &str, keyfile: Option<&str>) -> KeyMaterial {
    let keyfile = keyfile.map(|k| vault::read_keyfile(&fixture(k)).unwrap());
    KeyMaterial::new(Zeroizing::new(password.into()), keyfile).unwrap()
}

fn open(name: &str, key: KeyMaterial) -> Result<OpenDb, VaultError> {
    let path = fixture(name);
    let db = vault::open_database(&path, &key)?;
    Ok(OpenDb::new(path, None, key, None, db))
}

fn by_title(open: &OpenDb) -> HashMap<String, vault::IndexedEntry> {
    open.index.iter().map(|e| (e.title.clone(), e.clone())).collect()
}

#[test]
fn indexes_searchable_entries_only() {
    let open = open("password.kdbx", key(PASSWORD, None)).unwrap();
    let mut titles: Vec<&str> = open.index.iter().map(|e| e.title.as_str()).collect();
    titles.sort();
    // Not: "Old GitHub" (Recycle Bin), "Expired VPN" (expired), "Hidden thing" (searching off).
    assert_eq!(
        titles,
        ["Bank", "GitHub", "GitLab work", "Gitea home server", "Jira", "Kancelária Žilina", "Router"]
    );
    let entries = by_title(&open);
    let github = &entries["GitHub"];
    assert_eq!(github.group, "Personal/Dev");
    assert_eq!(github.username, "madev");
    assert_eq!(github.url_match, "github.com/login");
    assert_eq!(github.tags, "code git");
    assert!(github.has_password && github.has_totp && github.autotype);
    assert!(!entries["Router"].autotype);
    assert!(entries["Jira"].has_totp && entries["Bank"].has_totp);
    assert!(!entries["Gitea home server"].has_totp);
    assert_eq!(*entries["Jira"].notes, "Ask IT for the recovery codes.");
}

#[test]
fn wrong_credentials_are_reported() {
    assert_eq!(open("password.kdbx", key("nope", None)).err(), Some(VaultError::BadCredentials));
    assert_eq!(open("password-keyfile.kdbx", key(PASSWORD, None)).err(), Some(VaultError::BadCredentials));
    assert_eq!(
        open("password-keyfile.kdbx", key(PASSWORD, Some("raw.key"))).err(),
        Some(VaultError::BadCredentials)
    );
    assert!(matches!(open("missing.kdbx", key(PASSWORD, None)), Err(VaultError::NotFound(_))));
    assert!(matches!(open("fixture.xml", key(PASSWORD, None)), Err(VaultError::Format(_))));
    assert!(matches!(vault::read_keyfile(&fixture("missing.keyx")), Err(VaultError::NotFound(_))));
}

#[test]
fn opens_with_key_files() {
    let with_xml_keyfile =
        open("password-keyfile.kdbx", key(PASSWORD, Some("password-keyfile.keyx"))).unwrap();
    assert_eq!(with_xml_keyfile.index.len(), 7);
    let keyfile_only = open("keyfile-only.kdbx", key("", Some("raw.key"))).unwrap();
    assert_eq!(keyfile_only.index.len(), 7);
}

/// Re-encrypts the password fixture as KDBX 4 with the given KDF and cipher.
fn kdbx4_copy(dir: &Path, name: &str, kdf: KdfConfig, cipher: OuterCipherConfig) -> PathBuf {
    let mut db = Database::open(
        &mut std::fs::File::open(fixture("password.kdbx")).unwrap(),
        DatabaseKey::new().with_password(PASSWORD),
    )
    .unwrap();
    db.config.version = DatabaseVersion::KDB4(1);
    db.config.kdf_config = kdf;
    db.config.outer_cipher_config = cipher;
    db.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
    let path = dir.join(name);
    db.save(&mut std::fs::File::create(&path).unwrap(), DatabaseKey::new().with_password(PASSWORD)).unwrap();
    path
}

#[test]
fn opens_kdbx4_argon2() {
    let dir = tempfile::tempdir().unwrap();
    let argon = |memory| (2, memory, 2, rust_argon2::Version::Version13);
    let (iterations, memory, parallelism, version) = argon(16 * 1024 * 1024);
    let argon2d = kdbx4_copy(
        dir.path(),
        "argon2d-aes.kdbx",
        KdfConfig::Argon2 { iterations, memory, parallelism, version },
        OuterCipherConfig::AES256,
    );
    let (iterations, memory, parallelism, version) = argon(16 * 1024 * 1024);
    let argon2id = kdbx4_copy(
        dir.path(),
        "argon2id-chacha20.kdbx",
        KdfConfig::Argon2id { iterations, memory, parallelism, version },
        OuterCipherConfig::ChaCha20,
    );
    for path in [argon2d, argon2id] {
        let key = key(PASSWORD, None);
        let db = vault::open_database(&path, &key).unwrap();
        assert_eq!(vault::build_index(&db).len(), 7, "{}", path.display());
        let wrong = KeyMaterial::new(Zeroizing::new("wrong".into()), None).unwrap();
        assert_eq!(vault::open_database(&path, &wrong).err(), Some(VaultError::BadCredentials));
    }
}

struct EntryFields<'a>(&'a keepass::db::Entry);

impl Fields for EntryFields<'_> {
    fn field(&self, name: &str) -> Result<Option<Zeroizing<String>>, String> {
        let key = match name {
            "USERNAME" => "UserName",
            "PASSWORD" => "Password",
            other => other.strip_prefix("S:").unwrap_or(other),
        };
        Ok(self.0.get(key).map(|v| Zeroizing::new(v.to_string())))
    }
}

#[test]
fn autotype_sequences_and_secret_fields() {
    let open = open("password.kdbx", key(PASSWORD, None)).unwrap();
    let uuid = |title: &str| open.index.iter().find(|e| e.title == title).unwrap().uuid.clone();

    let gitlab = open.entry(&uuid("GitLab work")).unwrap();
    let seq = vault::autotype_sequence(&open.db, &gitlab, "{USERNAME}{TAB}{PASSWORD}{ENTER}");
    assert_eq!(seq, "{USERNAME}{TAB}{TAB}{PASSWORD}{ENTER}");

    let bank = open.entry(&uuid("Bank")).unwrap();
    assert_eq!(vault::autotype_sequence(&open.db, &bank, "{PASSWORD}"), "{PASSWORD}");
    let tokens = autotype::parse("{USERNAME}{TAB}{PASSWORD}{TAB}{S:PIN}", &EntryFields(&bank)).unwrap();
    let texts: Vec<String> = tokens
        .iter()
        .filter_map(|t| if let Token::Text(t) = t { Some(t.to_string()) } else { None })
        .collect();
    assert_eq!(texts, ["1234567", "čšž-ľťň", "4321"]);
}

#[test]
fn totp_from_all_three_formats() {
    let open = open("password.kdbx", key(PASSWORD, None)).unwrap();
    let uuid = |title: &str| open.index.iter().find(|e| e.title == title).unwrap().uuid.clone();
    for (title, digits) in [("GitHub", 6), ("Jira", 8), ("Bank", 6)] {
        let entry = open.entry(&uuid(title)).unwrap();
        let (code, valid_for) = totp::current_code(&entry).unwrap();
        assert_eq!(code.len(), digits, "{title}");
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        assert!((1..=30).contains(&valid_for));
    }
    let gitea = open.entry(&uuid("Gitea home server")).unwrap();
    assert!(totp::current_code(&gitea).is_err());
}

/// Opens `path` the way the daemon does: in an `open-db` helper process.
async fn open_in_helper(path: &Path, key: &KeyMaterial) -> Result<Database, VaultError> {
    Opener::spawn(Path::new(BIN), path, key).await?.wait().await
}

/// Everything in the database except the file-level settings the hand-over rewrites.
fn contents(db: &Database) -> serde_json::Value {
    let mut value = serde_json::to_value(db).unwrap();
    value.as_object_mut().unwrap().remove("config").expect("the crate serializes the config");
    value
}

/// The helper hands the database over re-encrypted; nothing may be lost or changed on the way.
#[tokio::test]
async fn the_helper_hands_over_the_same_database() {
    let dir = tempfile::tempdir().unwrap();
    let argon2id = kdbx4_copy(
        dir.path(),
        "argon2id.kdbx",
        KdfConfig::Argon2id {
            iterations: 2,
            memory: 16 * 1024 * 1024,
            parallelism: 2,
            version: rust_argon2::Version::Version13,
        },
        OuterCipherConfig::ChaCha20,
    );
    let cases = [
        (fixture("password.kdbx"), key(PASSWORD, None)),
        (fixture("password-keyfile.kdbx"), key(PASSWORD, Some("password-keyfile.keyx"))),
        (fixture("keyfile-only.kdbx"), key("", Some("raw.key"))),
        (argon2id, key(PASSWORD, None)),
    ];
    for (path, key) in cases {
        let direct = vault::open_database(&path, &key).unwrap();
        let handed_over =
            open_in_helper(&path, &key).await.unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(contents(&direct), contents(&handed_over), "{}", path.display());
        // And the daemon's view of it, which is what matters.
        let direct = OpenDb::new(path.clone(), None, key.clone(), None, direct);
        let handed_over = OpenDb::new(path.clone(), None, key, None, handed_over);
        assert_eq!(direct.index.len(), 7, "{}", path.display());
        for (a, b) in direct.index.iter().zip(&handed_over.index) {
            assert_eq!(
                (&a.uuid, &a.title, &a.username, &a.url, &a.group, &a.tags, &*a.notes),
                (&b.uuid, &b.title, &b.username, &b.url, &b.group, &b.tags, &*b.notes)
            );
            assert_eq!((a.has_password, a.has_totp, a.autotype), (b.has_password, b.has_totp, b.autotype));
            let (ea, eb) = (direct.entry(&a.uuid).unwrap(), handed_over.entry(&b.uuid).unwrap());
            assert_eq!(ea.get_password(), eb.get_password(), "{}", a.title);
            assert_eq!(
                vault::autotype_sequence(&direct.db, &ea, "{PASSWORD}"),
                vault::autotype_sequence(&handed_over.db, &eb, "{PASSWORD}")
            );
            if a.has_totp {
                assert_eq!(totp::current_code(&ea).unwrap().0, totp::current_code(&eb).unwrap().0);
            }
        }
    }
}

#[tokio::test]
async fn the_helper_reports_errors_like_the_in_process_open() {
    let bad = key("nope", None);
    assert_eq!(open_in_helper(&fixture("password.kdbx"), &bad).await.err(), Some(VaultError::BadCredentials));
    let missing = open_in_helper(&fixture("missing.kdbx"), &key(PASSWORD, None)).await;
    assert!(matches!(missing, Err(VaultError::NotFound(_))), "{missing:?}");
    let xml = open_in_helper(&fixture("fixture.xml"), &key(PASSWORD, None)).await;
    assert!(matches!(xml, Err(VaultError::Format(_))), "{xml:?}");
    // A helper that is not the daemon's binary cannot be started.
    let spawn = Opener::spawn(Path::new("/nonexistent/omakeepickd"), &fixture("password.kdbx"), &bad).await;
    assert!(matches!(spawn, Err(VaultError::Io(_))));
}
