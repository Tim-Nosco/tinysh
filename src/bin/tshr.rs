#![no_main]

extern crate libc;
#[macro_use]
extern crate lazy_static;
mod auxv;
mod kex;

#[allow(unused_imports)]
use aes_gcm::{Aes256Gcm, Key, Nonce};
#[allow(unused_imports)]
use anyhow::{anyhow, Result};
use auxv::getauxval;
use kex::{get_local_info, play_auth_challenge_remote, play_dh_kex_remote};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::ffi::CStr;
use std::fs::File;
use std::io::Write;
use std::net::TcpStream;
use std::os::unix::io::FromRawFd;
use std::sync::Mutex;

// Define some functions to work around the uclibc tools
lazy_static! {
    static ref STDIN: Mutex<File> = Mutex::new(unsafe { File::from_raw_fd(0) });
    static ref STDOUT: Mutex<File> = Mutex::new(unsafe { File::from_raw_fd(1) });
}
#[no_mangle]
pub fn open64(pathname: *const i8, oflag: i32) -> i32 {
    unsafe { libc::open(pathname, oflag) }
}

fn get_rand_seed(rand_ptr: *const u64) -> Option<u64> {
    if 0 != rand_ptr as usize {
        // Assuming everything worked out correctly, this dereference should be fine
        STDOUT
            .lock()
            .unwrap()
            .write(format!("deref rand bytes at: {:#016x}\n", rand_ptr as usize).as_bytes())
            .unwrap();
        Some(unsafe { *(rand_ptr) })
    } else {
        // getauxval(AT_RANDOM) is not available, use /dev/urandom
        None
    }
}

#[no_mangle]
pub fn main(argc: i32, argv: *const *const u8, envp: *const *const u8) -> i8 {
    // Build argv into rust vec
    let argv_vec = unsafe {
        let argv_vec_ptrs = std::slice::from_raw_parts(argv, argc as usize);
        argv_vec_ptrs
            .iter()
            .map(|x| {
                CStr::from_ptr(*x as *const i8)
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    };

    // Parse the IP addr and public key from argv
    let (ipaddr_b, pub_b) =
        get_local_info(argv_vec).expect("Failed to parse remote pub key and ip addr");
    STDOUT
        .lock()
        .unwrap()
        .write(format!("Found local's key:\n{:#}\n", pub_b.to_string()).as_bytes())
        .unwrap();

    // Seed the RNG
    // Prefer the auxiliary vector's random data entry for seeding
    let rand_ptr = getauxval(envp, libc::AT_RANDOM as usize).unwrap_or(0) as *const u64;
    let seed1 = get_rand_seed(rand_ptr);

    // TODO: Register SIGALRM

    // Open the socket to remote
    let mut remote = TcpStream::connect(format!("{}:2000", ipaddr_b)).expect("Unable to connect.");

    // Get the shared AES key
    let key = play_dh_kex_remote(&mut remote, &pub_b, seed1).expect("Failed KEX");

    // Create a new rng for the challenge and nonce values
    let mut rng = if let Some(seed2) = get_rand_seed(unsafe { rand_ptr.add(1) }) {
        ChaCha20Rng::seed_from_u64(seed2)
    } else {
        ChaCha20Rng::from_entropy()
    };

    // Challenge the remote
    play_auth_challenge_remote(&mut remote, &pub_b, &mut rng).expect("Failed challenge");

    // TODO: unregister SIGALRM

    return 0;
}
