#![no_main]

extern crate libc;

use std::fs::File;
use std::io::Write;
use std::os::unix::io::FromRawFd;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use p256::ecdh::EphemeralSecret;
use p256::PublicKey;
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha2::Sha256;
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

// Extract a key from the auxiliary vector starting the search from the environment pointer
#[no_mangle]
#[inline(never)]
fn getauxval(envp: *const *const u8, key: u32) -> Result<u32> {
    // First, find the end of the environment variables as denoted by a zero word
    let mut ptr_idx = 0;
    while unsafe { *envp.add(ptr_idx) } != (0 as *const u8) {
        ptr_idx += 1;
    }
    ptr_idx += 1;
    // Next, go through each 2-word auxv entry searching for the key
    let mut value;
    'auxp_iter: loop {
        let itr_key = unsafe { *envp.add(ptr_idx) as u32 };
        value = unsafe { *envp.add(ptr_idx + 1) as u32 };
        // We found the match
        if itr_key == key {
            break 'auxp_iter;
        }
        // We reached the end
        else if libc::AT_NULL == itr_key {
            return Err(anyhow!("Unable to find key in auxiliary vector."));
        }
        ptr_idx += 2;
    }
    Ok(value)
}

// Get remote's public key appended the end of this ELF
fn get_remote_key() -> Result<PublicKey> {
    // TODO: actually read from the tail of this file
    let test_str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdojljdsw2oUJ/CoGn6p9Bs30yKPd
pKK0Lb4fC+7c+9lnukYL5WOTsFzfUIZkGdrM5WyoEmDNISrh/mwzAB8m7w==
-----END PUBLIC KEY-----";
    Ok(PublicKey::from_str(test_str)?)
}

// Conduct the ECDH key exchange
fn play_dh_kex<T: RngCore + CryptoRng, A: Write>(
    writeable: &mut A,
    pub_b: PublicKey,
    rng: &mut T,
) -> Result<[u8; 32]> {
    // Generate local keys
    let secret_a = EphemeralSecret::random(rng);
    let pub_a = secret_a.public_key().to_string();
    writeable.write(pub_a.as_bytes())?;

    // Calculate the shared secret
    let secret_hkdf = secret_a.diffie_hellman(&pub_b).extract::<Sha256>(None);
    let mut key = [0u8; 32];
    secret_hkdf
        .expand(&vec![0u8; 0], &mut key)
        .or(Err(anyhow!("Unable to expand shared secret")))?;
    Ok(key)
}

#[no_mangle]
pub fn main(_argc: i32, _argv: *const *const u8, envp: *const *const u8) {
    // Setup stdio
    let (mut stdout, mut _stdin) = (stdout(), stdin());

    // Seed the RNG
    let rand_ptr = getauxval(envp, libc::AT_RANDOM).unwrap_or(0);
    let mut rng = if 0 != rand_ptr {
        ChaCha20Rng::seed_from_u64(unsafe { *(rand_ptr as *const u64) })
    } else {
        // getauxval(AT_RANDOM) is not available, use /dev/urandom
        ChaCha20Rng::from_entropy()
    };

    // Parse the elf header to find the tail of this executable
    //  this holds the remote's public key
    let pub_b = get_remote_key().expect("Failed to parse remote key");

    // Get the AES key
    let key = play_dh_kex(&mut stdout, pub_b, &mut rng).expect("Failed KEX");
    stdout.write(format!("{:#?}", key).as_bytes()).unwrap();
}
