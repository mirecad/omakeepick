//! A KDBX 4 file written by hand, a piece at a time.
//!
//! The `keepass` crate writes a database that it holds in memory. A test of what the helper
//! does with a file that unpacks to gigabytes needs one that nobody ever held, so this writes
//! the format itself: the compressed stream is fed zeros and never exists unpacked.

use std::io::Write;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use flate2::Compression;
use flate2::write::GzEncoder;
use hmac::{Hmac, Mac};
use keepass::config::{CompressionConfig, DatabaseVersion, KdfConfig};
use keepass::db::{Value, fields};
use keepass::{Database, DatabaseKey};
use sha2::{Digest, Sha256, Sha512};

const SIGNATURE: [u8; 8] = [0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5];
const CHACHA20: [u8; 16] = *b"\xd6\x03\x8a\x2b\x8b\x6f\x4c\xb5\xa5\x24\x33\x9a\x31\xdb\xb5\x9a";
const ARGON2D: [u8; 16] = *b"\xef\x63\x6d\xdf\x8c\x29\x44\x4b\x91\xf7\xa9\xa4\x03\xe3\x0a\x0c";

/// The title of the one entry in a file from [`with_attachment`].
pub const TITLE: &str = "Attached";

/// What the crate writes for a database with one entry, [`TITLE`], that has one attachment:
/// the XML alone. It names the attachment by its place in the inner header, not by its
/// contents, so it fits an attachment of any size.
fn xml() -> Vec<u8> {
    let mut db = Database::new();
    {
        let mut root = db.root_mut();
        let mut entry = root.add_entry();
        entry.set_unprotected(fields::TITLE, TITLE);
        entry.add_attachment("zeros", Value::unprotected(vec![0u8]));
    }
    db.config.version = DatabaseVersion::KDB4(1);
    db.config.kdf_config = KdfConfig::Aes { rounds: 1 };
    db.config.compression_config = CompressionConfig::None;
    let key = || DatabaseKey::new().with_password("x");
    let mut file = Vec::new();
    db.save(&mut file, key()).unwrap();
    let xml = Database::get_xml(&mut &file[..], key()).unwrap();
    // Nothing in it is encrypted under the inner key of the file it came from.
    assert!(!String::from_utf8_lossy(&xml).contains("Protected=\"True\""));
    xml
}

fn field(out: &mut Vec<u8>, kind: u8, bytes: &[u8]) {
    out.push(kind);
    out.extend((bytes.len() as u32).to_le_bytes());
    out.extend(bytes);
}

/// One item of a variant dictionary: 0x04 is a u32, 0x05 a u64, 0x42 bytes.
fn item(out: &mut Vec<u8>, kind: u8, name: &str, value: &[u8]) {
    out.push(kind);
    out.extend((name.len() as u32).to_le_bytes());
    out.extend(name.as_bytes());
    out.extend((value.len() as u32).to_le_bytes());
    out.extend(value);
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// A database under `password` whose one entry has an attachment of `attached` zero bytes,
/// compressed, as KeePassXC would save it. Its key derivation is Argon2d over `kdf_memory`
/// bytes. The file is about a thousandth of `attached`.
pub fn with_attachment(password: &str, attached: u64, kdf_memory: u64) -> Vec<u8> {
    let (master_seed, iv, salt) = ([1u8; 32], [2u8; 12], [3u8; 32]);
    let (iterations, lanes) = (2u64, 1u32);

    let mut kdf = vec![0x00, 0x01];
    item(&mut kdf, 0x42, "$UUID", &ARGON2D);
    item(&mut kdf, 0x42, "S", &salt);
    item(&mut kdf, 0x05, "M", &kdf_memory.to_le_bytes());
    item(&mut kdf, 0x05, "I", &iterations.to_le_bytes());
    item(&mut kdf, 0x04, "P", &lanes.to_le_bytes());
    item(&mut kdf, 0x04, "V", &0x13u32.to_le_bytes());
    kdf.push(0);

    let mut out = SIGNATURE.to_vec();
    out.extend([1, 0, 4, 0]); // version 4.1
    field(&mut out, 2, &CHACHA20);
    field(&mut out, 3, &1u32.to_le_bytes()); // compressed
    field(&mut out, 4, &master_seed);
    field(&mut out, 7, &iv);
    field(&mut out, 11, &kdf);
    field(&mut out, 0, b"\r\n\r\n");

    let composite = Sha256::digest(Sha256::digest(password.as_bytes()));
    let transformed = rust_argon2::hash_raw(
        &composite,
        &salt,
        &rust_argon2::Config {
            variant: rust_argon2::Variant::Argon2d,
            version: rust_argon2::Version::Version13,
            mem_cost: (kdf_memory / 1024) as u32,
            time_cost: iterations as u32,
            lanes,
            hash_length: 32,
            ..rust_argon2::Config::default()
        },
    )
    .unwrap();
    let master_key = Sha256::new().chain_update(master_seed).chain_update(&transformed).finalize();
    let hmac_key =
        Sha512::new().chain_update(master_seed).chain_update(&transformed).chain_update([1]).finalize();
    let block_key =
        |index: u64| Sha512::new().chain_update(index.to_le_bytes()).chain_update(hmac_key).finalize();

    let header_hash = Sha256::digest(&out);
    let header_mac = hmac(&block_key(u64::MAX), &[&out]);
    out.extend(header_hash);
    out.extend(header_mac);

    // The inner header (the cipher for protected values, its key, the attachment), then the
    // XML, all through the compressor.
    let mut packed = GzEncoder::new(Vec::new(), Compression::default());
    let mut inner = Vec::new();
    field(&mut inner, 1, &3u32.to_le_bytes());
    field(&mut inner, 2, &[7; 64]);
    packed.write_all(&inner).unwrap();
    let length = u32::try_from(attached + 1).expect("one attachment is under 4 GiB");
    packed.write_all(&[3]).unwrap();
    packed.write_all(&length.to_le_bytes()).unwrap();
    packed.write_all(&[0]).unwrap(); // its flags: not protected
    let zeros = vec![0u8; 1 << 20];
    let mut left = attached;
    while left > 0 {
        let now = left.min(zeros.len() as u64) as usize;
        packed.write_all(&zeros[..now]).unwrap();
        left -= now as u64;
    }
    packed.write_all(&[0, 0, 0, 0, 0]).unwrap(); // the end of the inner header
    packed.write_all(&xml()).unwrap();
    let mut payload = packed.finish().unwrap();

    chacha20::ChaCha20::new_from_slices(&master_key, &iv).unwrap().apply_keystream(&mut payload);

    // Blocks of a megabyte, each under its own key, and an empty one to end them.
    for (index, block) in payload.chunks(1 << 20).chain(std::iter::once(&[][..])).enumerate() {
        let index = index as u64;
        let length = (block.len() as u32).to_le_bytes();
        out.extend(hmac(&block_key(index), &[&index.to_le_bytes(), &length, block]));
        out.extend(length);
        out.extend(block);
    }
    out
}
