#![no_main]

extern crate libc;

use std::fs::File;
use std::io::Write;
use std::os::unix::io::FromRawFd;
use std::str::FromStr;

use p256::ecdh::EphemeralSecret;
use p256::PublicKey;
use sha2::Sha256;
use rand_chacha::ChaCha20Rng;
use rand_core::{SeedableRng, RngCore, CryptoRng};
use anyhow::Result;

#[allow(unused_imports)]
use aes_gcm::{Aes256Gcm, Key, Nonce};


// Define some functions to work around the uclibc tools
fn stdout() -> File {
    unsafe { File::from_raw_fd(1) }
}
fn stdin() -> File {
    unsafe { File::from_raw_fd(0) }
}
#[no_mangle]
pub fn open64(pathname: *const i8, oflag: i32) -> i32 {
    unsafe { libc::open(pathname, oflag) }
}

// Conduct the ECDH key exchange
fn play_dh_kex<T: RngCore+CryptoRng, A: Write>(writeable: &mut A, pub_b: PublicKey, rng: &mut T) -> Result<[u8;16]> {
    // Generate local keys
    let secret_a = EphemeralSecret::random(rng);
    let pub_a = secret_a.public_key().to_string();
    writeable.write(pub_a.as_bytes())?;

    // Calculate the shared secret
    let secret_hkdf = secret_a.diffie_hellman(&pub_b).extract::<Sha256>(None);
    let mut key = [0u8;16];
    secret_hkdf.expand(&vec![0u8;0], &mut key).expect("Unable to expand shared secret");
    Ok(key)
}

#[no_mangle]
pub fn main(_argc: i32, _argv: *const *const u8) {
    // Setup
    let (mut stdout, mut _stdin) = (stdout(), stdin());
    let mut rng = ChaCha20Rng::from_entropy();

    // Decode the remote's public key (appended to this ELF)
    let test_str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdojljdsw2oUJ/CoGn6p9Bs30yKPd
pKK0Lb4fC+7c+9lnukYL5WOTsFzfUIZkGdrM5WyoEmDNISrh/mwzAB8m7w==
-----END PUBLIC KEY-----";
    let pub_b = PublicKey::from_str(test_str).expect("Failed key parse");

    // Get the AES key
    let key = play_dh_kex(&mut stdout, pub_b, &mut rng).expect("Failed KEX");
    stdout.write(format!("{:#?}", key).as_bytes()).unwrap();
}
