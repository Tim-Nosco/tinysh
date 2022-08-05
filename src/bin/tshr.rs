#![no_main]

extern crate libc;
mod auxv;
mod kex;

#[allow(unused_imports)]
use aes_gcm::{Aes256Gcm, Key, Nonce};
#[allow(unused_imports)]
use anyhow::{anyhow, Result};
use auxv::getauxval;
use kex::{get_remote_info, play_auth_challenge_local, play_dh_kex_local};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::io::Write;
use std::str::FromStr;

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

#[no_mangle]
pub fn main(_argc: i32, _argv: *const *const u8, envp: *const *const u8) -> i8 {
    // Setup stdio
    let (mut stdout, mut _stdin) = (stdout(), stdin());

    // Parse the IP addr and public key from argv
    let (_ipaddr_b, pub_b) = get_remote_info().expect("Failed to parse remote pub key and ip addr");
    stdout.write(format!("found key:\n{:#}\n", pub_b.to_string()).as_bytes()).unwrap();

    // Seed the RNG
    // Prefer the auxiliary vector's random data entry for seeding
    let rand_ptr = getauxval(envp, libc::AT_RANDOM as usize).unwrap_or(0);
    let mut rng = if 0 != rand_ptr {
        // Assuming everything worked out correctly, this dereference should be fine
        // stdout.write(format!("{:#016x}\n", rand_ptr).as_bytes());
        let imd = unsafe { *(rand_ptr as *const u64) };
        ChaCha20Rng::seed_from_u64(imd)
    } else {
        // getauxval(AT_RANDOM) is not available, use /dev/urandom
        ChaCha20Rng::from_entropy()
    };

    // TODO: Open the socket to remote

    // Get the shared AES key
    let key = play_dh_kex_local(&mut stdout, pub_b, &mut rng).expect("Failed KEX");

    // Create a new rng for the challenge and nonce values
    rng = if 0 != rand_ptr {
        ChaCha20Rng::seed_from_u64(unsafe { *(rand_ptr as *const u64).add(1) })
    } else {
        ChaCha20Rng::from_entropy()
    };

    // Challenge the remote
    play_auth_challenge_local(&mut stdout, &key, &mut rng).expect("Failed challenge");

    return 0;
}
