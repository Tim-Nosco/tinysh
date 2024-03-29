#![allow(dead_code)]
extern crate libc;

use aes_gcm::{
	aead::{heapless::Vec, AeadInPlace, KeyInit},
	Aes256Gcm, Nonce,
};
use rand_core::RngCore;
use std::io::{Error, Read, Write};
use std::os::unix::io::AsRawFd;
use thiserror::Error;

#[allow(unused_imports)]
use crate::util::{copy_from_slice, debug};

// Use this struct to act like a socket with read and write calls
pub struct RelayNode<R, W> {
	pub readable: R,
	pub writeable: W,
}
// Call inner's read or write
impl<R: Read, W> Read for RelayNode<R, W> {
	fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
		self.readable.read(buf)
	}
}
impl<R, W: Write> Write for RelayNode<R, W> {
	fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
		self.writeable.write(buf)
	}
	fn flush(&mut self) -> Result<(), Error> {
		self.writeable.flush()
	}
}

#[derive(Error, Debug)]
pub enum IBError {
	#[error("Unable to copy memory to/from an InternalBuffer")]
	Copy,
	#[error("Unable to encrypt the InternalBuffer contents")]
	Encrypt,
	#[error("Unable to decrypt the InternalBuffer contents")]
	Decrypt,
}

// This is an internal buffer for storage of encrypted and decrypted
// messages  Encrypted messages will have the following form:
//  |--size--|---E(msg)---|
//  where size is 2 bytes in network-byte-order
//  and E(msg) is the encrypted message including:
//      - the nonce (12 bytes)
//      - the data
//      - the authentication tag (16 bytes)
type MsgSize = u16;
const MSG_SIZE_FIELD: usize = std::mem::size_of::<MsgSize>();
const MSG_NONCE_FIELD: usize = 12;
const MSG_AUTH_FIELD: usize = 16;
const MSG_BLOCK_SIZE: usize = 16;
const INTERNALBUF_MAX_SIZE: usize = 1024;
const INTERNALBUF_META: usize =
	MSG_SIZE_FIELD + MSG_NONCE_FIELD + MSG_AUTH_FIELD;
struct InternalBuf {
	pub buf: [u8; INTERNALBUF_MAX_SIZE],
	pub filled: usize,
}

impl InternalBuf {
	// After reading from buf, remove the used data
	fn clear(&mut self, amount: usize) {
		// Move data from self.buf[amount..filled] to
		// self.buf[0..filled-amount]
		if amount < self.filled {
			let mut tmp = [0u8; INTERNALBUF_MAX_SIZE];
			let _ = copy_from_slice(
				&mut tmp[0..self.filled - amount],
				&self.buf[amount..self.filled],
			);
			let _ = copy_from_slice(&mut self.buf[..], &tmp[..]);
		}
		// Update the remaining data count
		self.filled = self.filled.saturating_sub(amount);
	}
	// Determine how large the next decrypted message would be
	fn next_decrypt_len(&self) -> Option<usize> {
		// First, check if there's a full message to decrypt
		if self.filled >= MSG_SIZE_FIELD {
			let enc_msg_size = usize::from(MsgSize::from_be_bytes(
				self.buf[0..MSG_SIZE_FIELD].try_into().ok()?,
			))
			// This min ensures that a manipulated size field is still
			// bounded
			.min(INTERNALBUF_MAX_SIZE);
			if self.filled >= enc_msg_size {
				// Now calculate how big the decrypt would be
				Some(enc_msg_size.saturating_sub(INTERNALBUF_META))
			} else {
				None
			}
		} else {
			None
		}
	}
	// Take existing encrypted messages from self and write them into
	// another buffer
	fn decrypt_into(
		&mut self,
		dst: &mut InternalBuf,
		cipher: &mut Aes256Gcm,
	) -> Result<(), IBError> {
		// Make some space for decrypting
		let mut working: Vec<u8, INTERNALBUF_MAX_SIZE> = Vec::new();
		// while there's room to decrypt messages
		while let Some(decrypted_size) = self.next_decrypt_len() {
			// debug!("decrypting");
			if decrypted_size > dst.remains(true) {
				break;
			}
			// Pull out the nonce
			let nonce = Nonce::from_slice(
				&self.buf[MSG_SIZE_FIELD
					..MSG_SIZE_FIELD + MSG_NONCE_FIELD],
			);
			// Figure out where the ciphertext is (including auth tag)
			let start = MSG_SIZE_FIELD + MSG_NONCE_FIELD;
			let end = INTERNALBUF_META + decrypted_size;
			working
				.extend_from_slice(&self.buf[start..end])
				.or(Err(IBError::Copy))?;
			// Decrypt
			cipher
				.decrypt_in_place(nonce, b"", &mut working)
				.or(Err(IBError::Decrypt))?;
			// Copy into dst
			dst.extend(&working[..decrypted_size]);
			// Cleanup
			working.clear();
			self.clear(INTERNALBUF_META + decrypted_size);
		}
		Ok(())
	}
	// Add a msg to the unfilled part of the buffer if there's room
	//  otherwise, panic
	fn extend(&mut self, msg: &[u8]) {
		let _ = copy_from_slice(
			&mut self.buf[self.filled..self.filled + msg.len()],
			&msg,
		);
		self.filled += msg.len();
	}
	// Query how much space is left for new data
	fn remains(&self, raw: bool) -> usize {
		if raw {
			INTERNALBUF_MAX_SIZE.saturating_sub(self.filled)
		} else {
			// account for 2 byte size, 12 byte nonce, and 16 byte
			// auth tag if encrypted
			let pt_no_blocks = INTERNALBUF_MAX_SIZE
				.saturating_sub(self.filled + INTERNALBUF_META);
			// account for block size if using a scheme that needs it
			// pt_no_blocks.saturating_sub(pt_no_blocks %
			// MSG_BLOCK_SIZE)
			pt_no_blocks
		}
	}
	// Take data from self, encrypt it, and store it in another buffer
	fn encrypt_into<R>(
		&mut self,
		dst: &mut InternalBuf,
		cipher: &mut Aes256Gcm,
		rng: &mut R,
	) -> Result<(), IBError>
	where
		R: RngCore,
	{
		// calculate how much we can encrypt
		let mut max_msg_size = dst.remains(false);
		// ensure we don't pull more than we have
		max_msg_size = max_msg_size.min(self.filled);
		if max_msg_size > 0 {
			// debug!("encrypting {} bytes", max_msg_size);
			// Fill up the remaining space in dst with a new
			// message
			// Extract out the message we want to encrypt
			let mut msg: Vec<u8, INTERNALBUF_MAX_SIZE> = Vec::new();
			msg.extend_from_slice(&self.buf[0..max_msg_size])
				.or(Err(IBError::Copy))?;
			// Discard the used content
			self.clear(max_msg_size);
			// Make a new nonce
			let mut nonce_raw = [0u8; MSG_NONCE_FIELD];
			rng.try_fill_bytes(&mut nonce_raw)
				.or(Err(IBError::Copy))?;
			let nonce = Nonce::from_slice(&nonce_raw);
			// Encrypt the message
			cipher
				.encrypt_in_place(nonce, b"", &mut msg)
				.or(Err(IBError::Encrypt))?;
			// Build the encrypted message onto self.buf:
			//  |--size--|--nonce--|--ciphertext--|
			//  size:
			let total_size: MsgSize = (MSG_SIZE_FIELD
				+ nonce.len() + msg.len())
			.try_into()
			.or(Err(IBError::Copy))?;
			dst.extend(&total_size.to_be_bytes());
			//  nonce:
			dst.extend(&nonce);
			// ciphertext
			dst.extend(&msg[..msg.len()]);
		}
		Ok(())
	}
}

impl Default for InternalBuf {
	fn default() -> Self {
		Self {
			buf: [0; INTERNALBUF_MAX_SIZE],
			filled: 0,
		}
	}
}

#[derive(Error, Debug)]
pub enum RelayError {
	#[error("Unable to create new cipher")]
	Cipher,
	#[error("Unable to cast between types")]
	Cast,
	#[error("Poll errored")]
	Poll,
	#[error("Reading from fd failed")]
	Read,
	#[error("Remote sent the shutdown hint")]
	Shutdown,
	#[error("Writing to fd failed")]
	Write,
	#[error("Unable to encrypt buffer")]
	Encrypt,
	#[error("Invalid data in buffer to decrypt")]
	Decrypt,
}

// Encrypted relay between two nodes
pub fn relay<A, B, C, R>(
	// This can be stdin/stdout, pipes, etc.
	node0: &mut RelayNode<A, B>,
	// This should be the full-duplex remote connection
	node1: &mut C,
	// The shared key between ends of node1. Used for symmetric
	// encryption.
	key: &[u8; 32],
	// This rng is used to generate 12-byte nonces for each message
	rng: &mut R,
) -> Result<(), RelayError>
where
	A: Read + AsRawFd,
	B: Write + AsRawFd,
	C: Read + AsRawFd + Write,
	R: RngCore,
{
	// Create an array for fd events
	// 1 for side of the two duplexes
	let mut fds = [libc::pollfd {
		fd: 0,
		events: 0,
		revents: 0,
	}; 4];

	// Initialize the node0 & 1 file descriptors for use in poll.
	//  Both nodes are full duplex, so they each get two entries
	//  the most significant index bit represents the node number
	fds[0b00].fd = node0.readable.as_raw_fd(); // Read
	fds[0b01].fd = node0.writeable.as_raw_fd(); // Write
	fds[0b10].fd = (*node1).as_raw_fd(); // Read
	fds[0b10].fd = (*node1).as_raw_fd(); // Write

	// Set initial events
	fds[0b00].events |= libc::POLLIN;
	fds[0b10].events |= libc::POLLIN;

	// Create a buffer for each fds entry
	let mut bufs = [
		InternalBuf::default(),
		InternalBuf::default(),
		InternalBuf::default(),
		InternalBuf::default(),
	];

	// Initialize a cipher for recv and sends on node1
	let mut ciphers = [
		Aes256Gcm::new_from_slice(key).or(Err(RelayError::Cipher))?,
		Aes256Gcm::new_from_slice(key).or(Err(RelayError::Cipher))?,
	];

	loop {
		// Do the poll
		if unsafe {
			libc::poll(
				fds.as_mut_ptr(),
				fds.len().try_into().or(Err(RelayError::Cast))?,
				-1,
			)
		} <= 0
		{
			Err(RelayError::Poll)?;
		}
		// debug!("poll returns!");
		// Go through each revent and respond to POLLIN or POLLOUT as
		// needed
		for (idx, fd) in fds.iter().enumerate() {
			// Lookup the working buffer
			let mut buf = &mut bufs[idx];
			// Ready to recv
			if 0 < (fd.revents & libc::POLLIN) {
				// debug!("POLLIN on {}", idx);
				let max_recv = buf.remains(true);
				let this_node: &mut (dyn Read) =
					if 0 < (idx & 0b10) { node1 } else { node0 };
				let read_amt = this_node
					.read(
						&mut buf.buf
							[buf.filled..buf.filled + max_recv],
					)
					.or(Err(RelayError::Read))?;
				// debug!("- read: {} bytes", read_amt);
				if read_amt == 0 {
					// We got POLLIN, but read 0 bytes.
					// This is a polite way of conducting a socket
					// shutdown.
					Err(RelayError::Shutdown)?;
				}
				buf.filled += read_amt;
				// debug!("- filled {}: {}", idx, buf.filled);
			}
			// Ready to send
			if 0 < (fd.revents & libc::POLLOUT) {
				// debug!("POLLOUT on {}", idx);
				let this_node: &mut (dyn Write) =
					if 0 < (idx & 0b10) { node1 } else { node0 };
				let write_amt = this_node
					.write(&buf.buf[0..buf.filled])
					.or(Err(RelayError::Read))?;
				buf.clear(write_amt);
				this_node.flush().or(Err(RelayError::Write))?;
			}
		}

		// Encrypt / decrypt as needed
		// trickery to get two mutable pointers into bufs
		let (part0, part1) = bufs.split_at_mut(2);
		{
			// node0.writeable  <- D(c) <- node1.readable
			let src = 0b10;
			let dst = 0b01;
			part1[src & 1]
				.decrypt_into(
					&mut part0[dst & 1],
					&mut ciphers[src >> 1],
				)
				.or(Err(RelayError::Decrypt))?;
		}
		{
			// node0.readable   -> E(p) -> node1.writeable
			let src = 0b00;
			let dst = 0b11;
			part0[src & 1]
				.encrypt_into(
					&mut part1[dst & 1],
					&mut ciphers[src >> 1],
					rng,
				)
				.or(Err(RelayError::Encrypt))?;
		}

		// Set POLLIN and POLLOUT
		for idx in 0..fds.len() {
			// Clear the previous events
			fds[idx].events = 0;
			// This is a writeable
			if 0 < idx & 0b01 {
				// and there's stuff to write
				if 0 < bufs[idx].filled {
					// debug!("setting POLLOUT on {}", idx);
					fds[idx].events |= libc::POLLOUT;
				}
			}
			// Otherwise it's a readable
			else {
				// and there's room to read things
				if 0 < bufs[idx].remains(true) {
					// debug!("setting POLLIN on {}", idx);
					fds[idx].events |= libc::POLLIN;
				}
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand::rngs::SmallRng;
	use rand::SeedableRng;

	#[test]
	fn ib_new() {
		InternalBuf::default();
	}
	#[test]
	fn ib_clear() {
		// Make a new buffer
		let mut ib = InternalBuf::default();
		let msg = b"this is a test message";
		ib.extend(&msg[..]);
		// Clear out "this is a "
		let cleared = b"this is a ".len();
		ib.clear(cleared);
		// Make sure filled gets updated
		assert_eq!(ib.filled, msg.len() - cleared);
		// Make sure the remaining data is updated
		//  to "a test message"
		assert_eq!(ib.buf[0..ib.filled], msg[cleared..]);
	}
	#[test]
	fn ib_encrypt_decrypt() {
		// Test that encrypt and decrypt work together
		let mut ib0 = InternalBuf::default();
		let mut ib1 = InternalBuf::default();
		let mut ib2 = InternalBuf::default();
		// Start with some data in ib0
		let zeros = [0u8; 32];
		let mut rng = SmallRng::from_seed(zeros.clone());
		let mut msg = [0u8; 512];
		rng.try_fill_bytes(&mut msg).unwrap();
		ib0.extend(&msg);
		// Make a cipher for enc / dec
		let mut enc_cipher =
			Aes256Gcm::new_from_slice(&zeros).unwrap();
		let mut dec_cipher =
			Aes256Gcm::new_from_slice(&zeros).unwrap();
		// Encrypt from i0 to i1
		ib0.encrypt_into(&mut ib1, &mut enc_cipher, &mut rng)
			.unwrap();
		// Decrypt from i1 to i2
		ib1.decrypt_into(&mut ib2, &mut dec_cipher).unwrap();
		// Ensure we got the message back
		assert_eq!(&ib2.buf[..ib2.filled], &msg);
	}
	#[test]
	fn ib_encrypt_into_small() {
		// Create two buffers
		let mut src = InternalBuf::default();
		let mut dst = InternalBuf::default();
		// Add some data to encrypt
		let msg = b"12345 ==== this is a message ==== 6789";
		src.extend(&msg[..]);
		// Setup the cipher
		let key = [0u8; 32];
		let mut rng = SmallRng::from_seed(key.clone());
		let mut cipher = Aes256Gcm::new_from_slice(&key).unwrap();
		// Encrypt it into dst
		src.encrypt_into(&mut dst, &mut cipher, &mut rng).unwrap();
		// Test the output
		println!(
			"Encrypted size: {}\n{:02X?}",
			dst.filled,
			&dst.buf[0..dst.filled]
		);
		// The message size should be:
		//  MSG_SIZE_FIELD +
		//  MSG_NONCE_FIELD +
		//  msg.len() +
		//  MSG_AUTH_FIELD
		let expected_size: MsgSize =
			(INTERNALBUF_META + msg.len()).try_into().unwrap();
		assert_eq!(
			&dst.buf[0..MSG_SIZE_FIELD],
			expected_size.to_be_bytes()
		);
		// The nonce should be the same every time due to constant rng
		//  seed in this test:
		let nonce = vec![
			0xDF, 0x23, 0x0B, 0x49, 0x61, 0x5D, 0x17, 0x53, 0x3D,
			0x6F, 0xDA, 0x61,
		];
		assert_eq!(
			&dst.buf
				[MSG_SIZE_FIELD..MSG_SIZE_FIELD + MSG_NONCE_FIELD],
			&nonce
		);
		// The ct (excluding auth tag) should be this according to
		//  an independent encryption in python pycryptodome
		let ct = vec![
			0xDB, 0xCD, 0x70, 0x64, 0x8A, 0x2F, 0xCE, 0x68, 0x04,
			0xBC, 0xDC, 0xCA, 0xAA, 0x8B, 0x65, 0x54, 0x86, 0x6B,
			0x3A, 0xEB, 0xBF, 0xB3, 0x25, 0x64, 0x7B, 0x01, 0x8F,
			0x18, 0x18, 0xE7, 0x00, 0x9B, 0xF3, 0xDF, 0xCA, 0xDB,
			0xC8, 0x85,
		];
		let ct_start = MSG_SIZE_FIELD + MSG_NONCE_FIELD;
		assert_eq!(
			&dst.buf[ct_start..ct_start + ct.len()],
			&ct,
			"Ciphertext did not match the encrypted message."
		);
		// Check the auth tag (again according to python)
		let auth = vec![
			0xEB, 0x2E, 0x4C, 0x42, 0xF9, 0xA9, 0x15, 0x0F, 0x82,
			0x48, 0xAF, 0xD1, 0x7A, 0x64, 0x53, 0x89,
		];
		let auth_start = ct_start + ct.len();
		assert_eq!(&dst.buf[auth_start..dst.filled], &auth);
	}
	#[test]
	fn ib_encrypt_into_partial() {
		// Test when src has more data to encrypt than dst can support
		let mut src = InternalBuf::default();
		let mut dst = InternalBuf::default();
		// Start with some data in src
		let zeros = [0u8; 32];
		let mut rng = SmallRng::from_seed(zeros.clone());
		let mut msg = [0u8; 999];
		rng.try_fill_bytes(&mut msg).unwrap();
		src.extend(&msg);
		// Have dst only have room for 20 bytes
		dst.filled = INTERNALBUF_MAX_SIZE - INTERNALBUF_META - 20;
		// Make a cipher for encrypting
		let mut enc_cipher =
			Aes256Gcm::new_from_slice(&zeros).unwrap();
		// Encrypt from i0 to i1
		src.encrypt_into(&mut dst, &mut enc_cipher, &mut rng)
			.unwrap();
		// Ensure the right amount was copied
		assert_eq!(dst.filled, INTERNALBUF_MAX_SIZE);
		assert_eq!(src.filled, msg.len() - 20);
	}
	#[test]
	fn ib_decrypt_into_single_msg() {
		// Test when one message needs to be decrypted from src
		let mut src = InternalBuf::default();
		let mut dst = InternalBuf::default();
		// This ciphertext is generated from python pycryptodome:
		// AES.new(bytearray(32), AES.MODE_GCM, nonce=b"0123456789ab")
		//  .encrypt_and_digest(b'12345 ==== this is a message ====
		// 6789')
		let ct = vec![
			0x00, 0x44, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
			0x37, 0x38, 0x39, 0x61, 0x62, 0x27, 0xB4, 0x4E, 0x64,
			0x27, 0xD3, 0x96, 0xE9, 0xA0, 0x45, 0x3D, 0x1B, 0xF7,
			0xF4, 0x6B, 0xD2, 0x3B, 0x1D, 0xF9, 0x73, 0x9C, 0xE7,
			0xCD, 0x1B, 0x63, 0x49, 0x6E, 0xD8, 0x7E, 0xDD, 0x62,
			0x61, 0x2C, 0x37, 0x3F, 0x2A, 0xAD, 0xDD, 0x75, 0x62,
			0xAE, 0x7A, 0x42, 0x9B, 0xBA, 0xB3, 0x84, 0xBB, 0x72,
			0x4B, 0xD0, 0x8C, 0x5C, 0xD6,
		];
		src.extend(&ct);
		// Make a cipher for decrypting
		let zeros = [0u8; 32];
		let mut dec_cipher =
			Aes256Gcm::new_from_slice(&zeros).unwrap();
		// Decrypt
		src.decrypt_into(&mut dst, &mut dec_cipher).unwrap();
		// Check result
		let msg = b"12345 ==== this is a message ==== 6789";
		assert_eq!(&dst.buf[..dst.filled], &msg[..]);
	}
	#[test]
	fn ib_decrypt_into_multiple_msgs() {
		// Test when multiple messages are ready to be decrypted
		let mut src = InternalBuf::default();
		let mut dst = InternalBuf::default();
		// This ciphertext is generated from python pycryptodome:
		// AES.new(bytearray(32), AES.MODE_GCM, nonce=b"0123456789ab")
		//  .encrypt_and_digest(b'12345 ==== this is a message ====
		// 6789')
		let ct = vec![
			0x00, 0x44, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
			0x37, 0x38, 0x39, 0x61, 0x62, 0x27, 0xB4, 0x4E, 0x64,
			0x27, 0xD3, 0x96, 0xE9, 0xA0, 0x45, 0x3D, 0x1B, 0xF7,
			0xF4, 0x6B, 0xD2, 0x3B, 0x1D, 0xF9, 0x73, 0x9C, 0xE7,
			0xCD, 0x1B, 0x63, 0x49, 0x6E, 0xD8, 0x7E, 0xDD, 0x62,
			0x61, 0x2C, 0x37, 0x3F, 0x2A, 0xAD, 0xDD, 0x75, 0x62,
			0xAE, 0x7A, 0x42, 0x9B, 0xBA, 0xB3, 0x84, 0xBB, 0x72,
			0x4B, 0xD0, 0x8C, 0x5C, 0xD6,
		];
		src.extend(&ct);
		src.extend(&ct);
		// Make a cipher for decrypting
		let zeros = [0u8; 32];
		let mut dec_cipher =
			Aes256Gcm::new_from_slice(&zeros).unwrap();
		// Decrypt
		src.decrypt_into(&mut dst, &mut dec_cipher).unwrap();
		// Check result
		let msg = b"12345 ==== this is a message ==== 6789";
		assert_eq!(&dst.buf[..msg.len()], &msg[..]);
		assert_eq!(&dst.buf[msg.len()..2 * msg.len()], &msg[..]);
	}
	#[test]
	#[ignore]
	fn relay_encrypts() {
		todo!()
	}
	#[test]
	#[ignore]
	fn relay_send_and_recv() {
		todo!()
	}
}
