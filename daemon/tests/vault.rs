//! Opening real KDBX files. The fixtures were written by KeePassXC (`tests/fixtures/make.sh`);
//! the Argon2/ChaCha20 KDBX 4 variants are re-encrypted on the fly.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use keepass::config::{DatabaseVersion, InnerCipherConfig, KdfConfig, OuterCipherConfig};
use keepass::db::{Value, fields};
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
    // A sequence names its fields; the values come from the entry when they are typed.
    let tokens = autotype::parse("{USERNAME}{TAB}{PASSWORD}{TAB}{S:PIN}").unwrap();
    let fields = EntryFields(&bank);
    let values: Vec<String> = tokens
        .iter()
        .filter_map(|t| if let Token::Field(name) = t { fields.field(name).unwrap() } else { None })
        .map(|value| value.to_string())
        .collect();
    assert_eq!(values, ["1234567", "čšž-ľťň", "4321"]);
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

/// Opens `path` the way the daemon does: in an `open-db` helper process, which reads the files
/// first and is given `key` after that.
async fn open_in_helper(
    path: &Path,
    keyfile: Option<&Path>,
    key: KeyMaterial,
) -> Result<(Database, KeyMaterial), VaultError> {
    let mut opener = Opener::spawn(Path::new(BIN), path, keyfile).await?;
    opener.decrypt(key).await?.unseal()
}

fn password(password: &str) -> KeyMaterial {
    KeyMaterial::from_password(Zeroizing::new(password.into()))
}

/// Everything in the database except the file-level settings the hand-over rewrites.
fn contents(db: &Database) -> serde_json::Value {
    let mut value = serde_json::to_value(db).unwrap();
    value.as_object_mut().unwrap().remove("config").expect("the crate serializes the config");
    value
}

/// The helper hands the database over re-encrypted; nothing may be lost or changed on the way.
/// With it come the credentials it used: the password it was given and the key file it read.
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
        (fixture("password.kdbx"), PASSWORD, None),
        (fixture("password-keyfile.kdbx"), PASSWORD, Some("password-keyfile.keyx")),
        (fixture("keyfile-only.kdbx"), "", Some("raw.key")),
        (argon2id, PASSWORD, None),
    ];
    for (path, pass, keyfile) in cases {
        let whole = key(pass, keyfile);
        let mut direct = vault::open_database(&path, &whole).unwrap();
        // The hand-over leaves out what the daemon does not use; the fixtures have none of it.
        vault::strip(&mut direct);
        // An unlock: the helper reads the key file and is given the password alone.
        let (mut unlocked, used) = open_in_helper(&path, keyfile.map(fixture).as_deref(), password(pass))
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        // An empty history and none at all are the same thing, written two ways.
        vault::strip(&mut unlocked);
        assert_eq!(used.to_bytes(), whole.to_bytes(), "{}", path.display());
        assert_eq!(contents(&direct), contents(&unlocked), "{}", path.display());
        // A quick unlock or a reload: the key from memory, and no key file to read.
        let (mut reopened, used) = open_in_helper(&path, None, whole.clone())
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        vault::strip(&mut reopened);
        assert_eq!(used.to_bytes(), whole.to_bytes(), "{}", path.display());
        assert_eq!(contents(&direct), contents(&reopened), "{}", path.display());
        // And the daemon's view of it, which is what matters.
        let direct = OpenDb::new(path.clone(), None, whole.clone(), None, direct);
        let handed_over = OpenDb::new(path.clone(), None, whole, None, unlocked);
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

/// Saves `db` under `PASSWORD` and opens it through a helper.
async fn through_the_helper(db: &Database) -> Result<Database, VaultError> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("made.kdbx");
    db.save(&mut std::fs::File::create(&path).unwrap(), DatabaseKey::new().with_password(PASSWORD)).unwrap();
    open_in_helper(&path, None, password(PASSWORD)).await.map(|(db, _)| db)
}

/// The daemon is handed what it uses and nothing else: attachments and the earlier versions of
/// entries, so old passwords, stay in the helper, which ends.
#[tokio::test]
async fn the_helper_hands_over_only_what_the_daemon_uses() {
    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(fields::TITLE, "Mail");
        entry.set_protected(fields::PASSWORD, "the-old-password");
        entry.add_attachment("recovery-codes.txt", Value::protected(b"attached-recovery-codes".to_vec()));
        entry.set_icon_custom_new(vec![1, 2, 3, 4]);
        // Changing it under `track_changes` files the version above in the entry's history.
        entry.track_changes().set_protected(fields::PASSWORD, "the-current-password");
    }
    let before = serde_json::to_string(&db).unwrap();
    for part in ["the-old-password", "the-current-password", "recovery-codes.txt"] {
        assert!(before.contains(part), "the database was not built with {part}");
    }
    assert_eq!((db.num_attachments(), db.num_custom_icons()), (1, 1));
    // Built in memory, the database knows which versions use the icon and the attachment in
    // another way than one read from a file does. Taking them out has to cope with both.
    let mut built = db.clone();
    vault::strip(&mut built);
    assert_eq!((built.num_attachments(), built.num_custom_icons()), (0, 0));

    let handed_over = through_the_helper(&db).await.unwrap();
    let after = serde_json::to_string(&handed_over).unwrap();
    assert!(after.contains("the-current-password"));
    for part in ["the-old-password", "recovery-codes.txt"] {
        assert!(!after.contains(part), "{part} was handed over");
    }
    assert_eq!(handed_over.num_attachments(), 0);
    let open = OpenDb::new(PathBuf::new(), None, password(PASSWORD), None, handed_over);
    assert_eq!(open.index.len(), 1);
    assert_eq!(open.entry(&open.index[0].uuid).unwrap().get_password(), Some("the-current-password"));
}

/// The same for a database as KeePassXC writes it (`tests/fixtures/extras.xml`): a downloaded
/// icon on an entry, on an earlier version of it and on a group; two earlier versions with
/// other passwords; an attachment that only an earlier version has, and one that two entries
/// share. Read from a file, such things refer to each other in ways a database built in
/// memory does not show.
#[tokio::test]
async fn a_keepassxc_database_is_handed_over_without_its_extras() {
    let path = fixture("extras.kdbx");
    let extras =
        ["the-old-password", "the-older-password", "recovery-codes.txt", "old-codes.txt", "shared.txt"];
    let mut direct = vault::open_database(&path, &key(PASSWORD, None)).unwrap();
    let before = serde_json::to_string(&direct).unwrap();
    for part in extras {
        assert!(before.contains(part), "the fixture has no {part}");
    }
    assert_eq!((direct.num_attachments(), direct.num_custom_icons()), (2, 1));

    // What the helper does to it before it is sealed: no trace of them is left to be written.
    vault::strip(&mut direct);
    let stripped = serde_json::to_string(&direct).unwrap();
    for part in extras {
        assert!(!stripped.contains(part), "{part} is still in the database");
    }
    assert_eq!((direct.num_attachments(), direct.num_custom_icons()), (0, 0));

    let (handed_over, _) = open_in_helper(&path, None, password(PASSWORD)).await.unwrap();
    assert_eq!(contents(&direct), {
        let mut handed_over = handed_over.clone();
        vault::strip(&mut handed_over);
        contents(&handed_over)
    });
    let open = OpenDb::new(path, None, password(PASSWORD), None, handed_over);
    let found: Vec<(&str, &str)> = open.index.iter().map(|e| (e.title.as_str(), e.group.as_str())).collect();
    assert_eq!(found, [("Plain", ""), ("Webmail", "Mail")]);
    let webmail = open.entry(&open.index[1].uuid).unwrap();
    assert_eq!(webmail.get_password(), Some("the-current-password"));
}

/// What the daemon takes apart itself, on a thread a lock cannot stop, has a size that the
/// helper decides, not the file: attachments do not count, since they are not handed over, and
/// a database with more text than the limit is refused in the helper.
#[tokio::test]
async fn the_hand_over_has_a_size_the_file_does_not_decide() {
    let megabytes = |db: &mut Database, megabytes: usize, attached: usize| {
        let mut root = db.root_mut();
        for i in 0..megabytes {
            let mut entry = root.add_entry();
            entry.set_unprotected(fields::TITLE, format!("Entry {i}"));
            entry.set_unprotected(fields::NOTES, "n".repeat(1 << 20));
            entry.add_attachment("blob", Value::unprotected(vec![7u8; attached]));
        }
    };
    // 40 MiB of attachments on 2 MiB of text: fine.
    let mut db = Database::new();
    megabytes(&mut db, 2, 20 << 20);
    assert_eq!(through_the_helper(&db).await.unwrap().num_entries(), 2);
    // 40 MiB of text, which compresses to nothing in the file: refused.
    let mut db = Database::new();
    megabytes(&mut db, 40, 0);
    match through_the_helper(&db).await {
        Err(VaultError::Format(message)) => assert!(message.contains("too large"), "{message}"),
        other => panic!("{:?}", other.map(|db| db.num_entries())),
    }
}

#[tokio::test]
async fn the_helper_reports_errors_like_the_in_process_open() {
    let open = async |name: &str, keyfile: Option<&str>, pass: &str| {
        open_in_helper(&fixture(name), keyfile.map(fixture).as_deref(), password(pass)).await.err()
    };
    assert_eq!(open("password.kdbx", None, "nope").await, Some(VaultError::BadCredentials));
    assert_eq!(open("password-keyfile.kdbx", None, PASSWORD).await, Some(VaultError::BadCredentials));
    assert_eq!(
        open("password-keyfile.kdbx", Some("raw.key"), PASSWORD).await,
        Some(VaultError::BadCredentials)
    );
    let missing = open("missing.kdbx", None, PASSWORD).await;
    assert!(matches!(missing, Some(VaultError::NotFound(_))), "{missing:?}");
    let xml = open("fixture.xml", None, PASSWORD).await;
    assert!(matches!(xml, Some(VaultError::Format(_))), "{xml:?}");
    // Neither a password nor a key file.
    let nothing = open("password.kdbx", None, "").await;
    assert!(matches!(nothing, Some(VaultError::BadRequest(_))), "{nothing:?}");
    // A helper that is not the daemon's binary cannot be started.
    let spawn = Opener::spawn(Path::new("/nonexistent/omakeepickd"), &fixture("password.kdbx"), None).await;
    assert!(matches!(spawn.err(), Some(VaultError::Io(_))));
}

/// The helper's half of the order that keeps credentials away from file reads, which can hang:
/// it reads both files, and refuses what it can refuse, before it is given any credential.
#[tokio::test]
async fn the_helper_reads_the_files_before_it_is_given_credentials() {
    let exe = Path::new(BIN);
    let db = fixture("password-keyfile.kdbx");
    let keyfile = fixture("password-keyfile.keyx");
    // `spawn` takes no credentials, so none have been sent when `read` returns.
    let mut opener = Opener::spawn(exe, &db, Some(&keyfile)).await.unwrap();
    assert_eq!(opener.read().await.unwrap(), vault::read_database(&db).unwrap().1);
    // Sent now, they open the database, and the key file's contents come back with it.
    let (opened, used) = opener.decrypt(password(PASSWORD)).await.unwrap().unseal().unwrap();
    assert_eq!(vault::build_index(&opened).len(), 7);
    assert_eq!(used.to_bytes(), key(PASSWORD, Some("password-keyfile.keyx")).to_bytes());

    // A key file or a database that cannot be read ends it there, credentials unsent.
    let dir = tempfile::tempdir().unwrap();
    let read = async |db: &Path, keyfile: Option<&Path>| {
        Opener::spawn(exe, db, keyfile).await.unwrap().read().await.err()
    };
    let gone = fixture("missing.keyx");
    assert_eq!(read(&db, Some(&gone)).await, Some(VaultError::NotFound(gone)));
    let not_a_file = read(&db, Some(dir.path())).await;
    assert!(matches!(not_a_file, Some(VaultError::Keyfile(_))), "{not_a_file:?}");
    let gone = fixture("missing.kdbx");
    assert_eq!(read(&gone, Some(&keyfile)).await, Some(VaultError::NotFound(gone)));

    // So does a header that asks for a derivation without end (KDBX 3 field 6, the rounds).
    let mut absurd = std::fs::read(fixture("password.kdbx")).unwrap();
    let mut at = 12;
    while absurd[at] != 6 {
        at += 3 + u16::from_le_bytes([absurd[at + 1], absurd[at + 2]]) as usize;
    }
    absurd[at + 3..at + 11].copy_from_slice(&u64::MAX.to_le_bytes());
    let path = dir.path().join("absurd.kdbx");
    std::fs::write(&path, absurd).unwrap();
    let refused = read(&path, None).await;
    assert!(matches!(refused, Some(VaultError::Format(_))), "{refused:?}");
}

/// The daemon's half of that order: it writes no credential until the helper has reported the
/// files as read. The stand-in helper here never does, and after a second reports how many
/// bytes it was sent: the request naming the two files, and nothing else.
#[tokio::test]
async fn credentials_are_not_sent_before_the_files_are_read() {
    let db = fixture("password-keyfile.kdbx");
    let keyfile = fixture("password-keyfile.keyx");
    let mut opener = Opener::spawn(&fixture("never-ready.sh"), &db, Some(&keyfile)).await.unwrap();
    let outcome = opener.decrypt(password(PASSWORD)).await.err();
    let request = 4 + db.as_os_str().len() + 4 + keyfile.as_os_str().len();
    assert_eq!(outcome, Some(VaultError::Io(request.to_string())));
}
