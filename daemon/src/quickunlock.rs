//! PIN quick unlock.
//!
//! After a full unlock with a PIN, the key material is kept encrypted with
//! `ChaCha20Poly1305(Argon2id(pin, salt))`. The blob only ever lives in this process's memory:
//! it is gone after a reboot, suspend, `close`, or [`MAX_ATTEMPTS`] wrong PINs.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::{Zeroize, Zeroizing};

use crate::vault::KeyMaterial;

pub const MAX_ATTEMPTS: u32 = 3;
pub const MIN_PIN_LEN: usize = 4;

/// Argon2id cost: 64 MiB, 3 passes. Slows down guessing without making quick unlock sluggish.
const MEMORY_KIB: u32 = 64 * 1024;
const PASSES: u32 = 3;

pub struct QuickBlob {
    salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    attempts_left: u32,
}

/// The blob is the credentials under a key that a four-digit PIN gives away to anyone who can
/// try them all, so it is wiped like the credentials themselves, not just freed.
impl Zeroize for QuickBlob {
    fn zeroize(&mut self) {
        self.ciphertext.zeroize();
        self.salt.zeroize();
        self.nonce.zeroize();
        self.attempts_left = 0;
    }
}

impl Drop for QuickBlob {
    fn drop(&mut self) {
        self.zeroize();
    }
}

fn derive(pin: &str, salt: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let params = Params::new(MEMORY_KIB, PASSES, 1, Some(32)).expect("static Argon2 parameters");
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pin.as_bytes(), salt, out.as_mut())
        .expect("Argon2 output length is valid");
    out
}

fn cipher(pin: &str, salt: &[u8; 16]) -> ChaCha20Poly1305 {
    let key = derive(pin, salt);
    ChaCha20Poly1305::new(&Key::from(*key))
}

pub fn validate_pin(pin: &str) -> Result<(), String> {
    if pin.chars().count() < MIN_PIN_LEN {
        return Err(format!("The PIN needs at least {MIN_PIN_LEN} characters"));
    }
    Ok(())
}

impl QuickBlob {
    /// Encrypts `key` with `pin`. `context` (the database path) is bound as associated data.
    pub fn seal(pin: &str, key: &KeyMaterial, context: &[u8]) -> Result<Self, String> {
        validate_pin(pin)?;
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut salt).map_err(|e| e.to_string())?;
        getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
        let plaintext = key.to_bytes();
        let ciphertext = cipher(pin, &salt)
            .encrypt(&Nonce::from(nonce), Payload { msg: &plaintext, aad: context })
            .map_err(|_| "Encryption failed".to_string())?;
        Ok(QuickBlob { salt, nonce, ciphertext, attempts_left: MAX_ATTEMPTS })
    }

    pub fn attempts_left(&self) -> u32 {
        self.attempts_left
    }

    /// Decrypts the key material. A wrong PIN costs one attempt; the caller must drop the blob
    /// once [`attempts_left`](Self::attempts_left) reaches zero.
    pub fn open(&mut self, pin: &str, context: &[u8]) -> Option<KeyMaterial> {
        let plaintext = cipher(pin, &self.salt)
            .decrypt(&Nonce::from(self.nonce), Payload { msg: &self.ciphertext, aad: context })
            .ok()
            .map(Zeroizing::new);
        match plaintext.as_deref().and_then(|bytes| KeyMaterial::from_bytes(bytes)) {
            Some(key) => {
                self.attempts_left = MAX_ATTEMPTS;
                Some(key)
            }
            None => {
                self.attempts_left = self.attempts_left.saturating_sub(1);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> KeyMaterial {
        KeyMaterial::new(Zeroizing::new("master".into()), None).unwrap()
    }

    /// A blob that is dropped (a sleep, three wrong PINs, closing) is wiped, not just freed.
    #[test]
    fn a_dropped_blob_is_wiped() {
        // What wiping does, on one that can still be looked at: the ciphertext above all.
        let mut blob = QuickBlob::seal("2468", &key(), b"/db").unwrap();
        let sealed = blob.ciphertext.len();
        assert!(sealed > 16 && blob.ciphertext.iter().any(|&b| b != 0));
        blob.zeroize();
        assert!(blob.ciphertext.is_empty() && blob.ciphertext.capacity() >= sealed);
        // SAFETY: `Vec::zeroize` has written zeroes over all of the capacity.
        let room = blob.ciphertext.spare_capacity_mut();
        assert!(room.iter().all(|b| unsafe { b.as_ptr().read() } == 0));
        assert_eq!((blob.salt, blob.nonce, blob.attempts_left), ([0; 16], [0; 12], 0));

        // And dropping one does that.
        let mut blob = std::mem::ManuallyDrop::new(QuickBlob::seal("2468", &key(), b"/db").unwrap());
        assert_ne!((blob.salt, blob.nonce), ([0; 16], [0; 12]));
        // SAFETY: dropped once, here; only the plain arrays it leaves behind are looked at.
        unsafe { std::mem::ManuallyDrop::drop(&mut blob) };
        assert_eq!((blob.salt, blob.nonce), ([0; 16], [0; 12]));
    }

    #[test]
    fn right_pin_opens_and_resets_attempts() {
        let mut blob = QuickBlob::seal("2468", &key(), b"/db").unwrap();
        assert!(blob.open("1111", b"/db").is_none());
        assert_eq!(blob.attempts_left(), MAX_ATTEMPTS - 1);
        assert!(blob.open("2468", b"/db").is_some());
        assert_eq!(blob.attempts_left(), MAX_ATTEMPTS);
    }

    #[test]
    fn wrong_pins_run_out_and_context_is_bound() {
        let mut blob = QuickBlob::seal("2468", &key(), b"/db").unwrap();
        assert!(blob.open("2468", b"/other").is_none());
        assert!(blob.open("0000", b"/db").is_none());
        assert!(blob.open("0001", b"/db").is_none());
        assert_eq!(blob.attempts_left(), 0);
    }

    #[test]
    fn short_pins_are_rejected() {
        assert!(QuickBlob::seal("123", &key(), b"/db").is_err());
        assert!(validate_pin("1234").is_ok());
    }
}
