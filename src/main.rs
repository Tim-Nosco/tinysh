#![no_main]

extern crate libc;

use std::fs::File;
use std::io::Write;
use std::os::unix::io::FromRawFd;
use std::str::FromStr;
use std::ffi::CStr;

use p256::ecdh::EphemeralSecret;
use p256::PublicKey;
use sha2::Sha256;
use rand_chacha::ChaCha20Rng;
use rand_core::{SeedableRng, RngCore, CryptoRng};
use anyhow::{anyhow, Result};
// use thiserror::Error;

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

// Get remote's public key appended the end of this ELF
fn get_remote_key(filename: &str) -> Result<PublicKey> {
    // TODO: actually read from the tail of this file
    let test_str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdojljdsw2oUJ/CoGn6p9Bs30yKPd
pKK0Lb4fC+7c+9lnukYL5WOTsFzfUIZkGdrM5WyoEmDNISrh/mwzAB8m7w==
-----END PUBLIC KEY-----";
    Ok(PublicKey::from_str(test_str)?)
}

// Conduct the ECDH key exchange
fn play_dh_kex<T: RngCore+CryptoRng, A: Write>(writeable: &mut A, pub_b: PublicKey, rng: &mut T) -> Result<[u8;32]> {
    // Generate local keys
    let secret_a = EphemeralSecret::random(rng);
    let pub_a = secret_a.public_key().to_string();
    writeable.write(pub_a.as_bytes())?;

    // Calculate the shared secret
    let secret_hkdf = secret_a.diffie_hellman(&pub_b).extract::<Sha256>(None);
    let mut key = [0u8;32];
    secret_hkdf.expand(&vec![0u8;0], &mut key).or(Err(anyhow!("Unable to expand shared secret")))?;
    Ok(key)
}


#[no_mangle]
pub fn main(argc: i32, argv: *const *const u8) {
    // Setup
    let (mut stdout, mut _stdin) = (stdout(), stdin());
    let mut rng = ChaCha20Rng::from_entropy();
    
    // TODO: use /proc/self/exe
    let pub_b = if argc > 0 {
        // Interpret argv0 as the filename for the current binary
        let raw_argv0 = unsafe { CStr::from_ptr(*argv as *const i8) };
        get_remote_key(raw_argv0.to_str().unwrap())
    } else {
        Err(anyhow!("Not enough arguments in argv"))
    }.expect("Failed to parse remote key");
    
    // Get the AES key
    let key = play_dh_kex(
        &mut stdout, pub_b, &mut rng
    ).expect("Failed KEX");
    stdout.write(format!("{:#?}", key).as_bytes()).unwrap();
}
