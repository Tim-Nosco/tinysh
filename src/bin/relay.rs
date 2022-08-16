#![allow(dead_code)]
extern crate libc;

use aes_gcm::{
	aead::{Aead, KeyInit},
	Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use rand_core::{CryptoRng, RngCore};
use std::io::{Error, Read, Write};
use std::os::unix::io::AsRawFd;

use super::debug;

pub trait ReadFd = Read + AsRawFd;
pub trait WriteFd = Write + AsRawFd;
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

// This is an internal buffer for storage of encrypted and decrypted
// messages  Encrypted messages will have the following form:
//  |--size--|---E(msg)---|
//  where size is 2 bytes in network-byte-order
//  and E(msg) is the encrypted message including:
//      - the nonce (12 bytes)
//      - the data
//      - the authentication tag (16 bytes)
const MSG_SIZE_FIELD: usize = 2;
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
			tmp[0..self.filled - amount]
				.copy_from_slice(&self.buf[amount..self.filled]);
			self.buf[..].copy_from_slice(&tmp[..]);
		}
		// Update the remaining data count
		self.filled = self.filled.saturating_sub(amount);
	}
	// Determine how large the next decrypted message would be
	fn next_decrypt_len(&self) -> Option<usize> {
		// First, check if there's a full message to decrypt
		if self.filled >= MSG_SIZE_FIELD {
			let enc_msg_size = usize::from(u16::from_be_bytes(
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
	// Return a decrypted message from the interal buffer (and clear
	// decrypted)
	fn decrypt(&mut self, cipher: &mut Aes256Gcm) -> Result<Vec<u8>> {
		// Check that there's a full message
		if let Some(dec_msg_size) = self.next_decrypt_len() {
			let nonce = Nonce::from_slice(
				&self.buf[MSG_SIZE_FIELD
					..MSG_SIZE_FIELD + MSG_NONCE_FIELD],
			);
			let pt = cipher
				.decrypt(
					nonce,
					&self.buf[MSG_SIZE_FIELD + MSG_NONCE_FIELD
						..INTERNALBUF_META + dec_msg_size],
				)
				.or(Err(anyhow!("Unable to decrypt")));
			self.clear(INTERNALBUF_META + dec_msg_size);
			pt
		} else {
			Err(anyhow!("Not enough data to decrypt completely"))
		}
	}
	// Take existing encrypted messages from self and write them into
	// another buffer
	fn decrypt_into(
		&mut self,
		dst: &mut InternalBuf,
		cipher: &mut Aes256Gcm,
	) -> Result<()> {
		// while there's room to decrypt messages
		while let Some(decrypted_size) = self.next_decrypt_len() {
			debug!("decrypting");
			if decrypted_size > dst.remains(true) {
				break;
			}
			let msg = self.decrypt(cipher)?;
			let filled = dst.filled;
			dst.buf[filled..filled + msg.len()].copy_from_slice(&msg);
			dst.filled += msg.len();
		}
		Ok(())
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
			// account for block size
			pt_no_blocks.saturating_sub(pt_no_blocks % MSG_BLOCK_SIZE)
		}
	}
	// Add data to the buffer, encrypting it first
	fn extend_encrypted<R>(
		&mut self,
		cipher: &mut Aes256Gcm,
		msg: &[u8],
		rng: &mut R,
	) -> Result<()>
	where
		R: RngCore,
	{
		// Make a new nonce
		let mut nonce_raw = [0u8; MSG_NONCE_FIELD];
		rng.try_fill_bytes(&mut nonce_raw)?;
		let nonce = Nonce::from_slice(&nonce_raw);
		// Encrypt the message
		let ct = cipher
			.encrypt(nonce, msg)
			.or(Err(anyhow!("Unable to encrypt.")))?;
		// Build the encrypted message onto self.buf:
		//  |--size--|--nonce--|--ciphertext--|
		//  size:
		let total_size: u16 =
			(MSG_SIZE_FIELD + nonce.len() + ct.len()).try_into()?;
		self.buf[self.filled..self.filled + MSG_SIZE_FIELD]
			.copy_from_slice(&total_size.to_be_bytes());
		self.filled += MSG_SIZE_FIELD;
		//  nonce:
		self.buf[self.filled..self.filled + nonce.len()]
			.copy_from_slice(&nonce);
		self.filled += nonce.len();
		// ciphertext
		self.buf[self.filled..self.filled + ct.len()]
			.copy_from_slice(&ct);
		self.filled += ct.len();
		Ok(())
	}
	// Take data from self, encrypt it, and store it in another buffer
	fn encrypt_into<R>(
		&mut self,
		dst: &mut InternalBuf,
		cipher: &mut Aes256Gcm,
		rng: &mut R,
	) -> Result<()>
	where
		R: RngCore + CryptoRng,
	{
		// calculate how much we can encrypt
		let mut max_msg_size = dst.remains(false);
		// ensure we don't pull more than we have
		max_msg_size = max_msg_size.min(self.filled);
		if max_msg_size > 0 {
			debug!("encrypting {} bytes", max_msg_size);
			// Fill up the remaining space in dst with a new
			// message
			// Next, extract out the message we want to encrypt
			let msg = &self.buf[0..max_msg_size];
			// Encrypt it
			dst.extend_encrypted(cipher, &msg, rng)?;
			// Discard the used content
			self.clear(msg.len());
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
) -> Result<()>
where
	A: ReadFd,
	B: WriteFd,
	C: ReadFd + WriteFd,
	R: CryptoRng + RngCore,
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
	let mut bufs = vec![
		InternalBuf::default(),
		InternalBuf::default(),
		InternalBuf::default(),
		InternalBuf::default(),
	];

	// Initialize a cipher for recv and sends on node1
	let mut ciphers = vec![
		Aes256Gcm::new_from_slice(key)?,
		Aes256Gcm::new_from_slice(key)?,
	];

	loop {
		// Do the poll
		if unsafe {
			libc::poll(fds.as_mut_ptr(), fds.len().try_into()?, -1)
		} < 0
		{
			Err(anyhow!("Error using poll."))?;
		}
		debug!("poll returns!");
		// Go through each revent and respond to POLLIN or POLLOUT as
		// needed
		for (idx, fd) in fds.iter().enumerate() {
			// Lookup the working buffer
			let mut buf = &mut bufs[idx];
			// Ready to recv
			if 0 < (fd.revents & libc::POLLIN) {
				debug!("POLLIN on {}", idx);
				let max_recv = buf.remains(true);
				let this_node: &mut (dyn Read) =
					if 0 < (idx & 0b10) { node1 } else { node0 };
				let read_amt = this_node.read(
					&mut buf.buf[buf.filled..buf.filled + max_recv],
				)?;
				debug!("- read: {} bytes", read_amt);
				if read_amt == 0 {
					// We got POLLIN, but read 0 bytes.
					// This is a polite way of conducting a socket
					// shutdown.
					Err(anyhow!("Node shutdown"))?;
				}
				buf.filled += read_amt;
				debug!("- filled {}: {}", idx, buf.filled);
			}
			// Ready to send
			if 0 < (fd.revents & libc::POLLOUT) {
				debug!("POLLOUT on {}", idx);
				let this_node: &mut (dyn Write) =
					if 0 < (idx & 0b10) { node1 } else { node0 };
				buf.clear(this_node.write(&buf.buf[0..buf.filled])?);
				this_node.flush()?;
			}
		}

		// Encrypt / decrypt as needed
		// trickery to get two mutable pointers into bufs
		let (part0, part1) = bufs.split_at_mut(2);
		// node0.writeable  <- D(c) <- node1.readable
		{
			let src = 0b10;
			let dst = 0b01;
			part1[src & 1].decrypt_into(
				&mut part0[dst & 1],
				&mut ciphers[src >> 1],
			)?;
		}
		// node0.readable   -> E(p) -> node1.writeable
		{
			let src = 0b00;
			let dst = 0b11;
			part0[src & 1].encrypt_into(
				&mut part1[dst & 1],
				&mut ciphers[src >> 1],
				rng,
			)?;
		}

		// Set POLLIN and POLLOUT
		for idx in 0..fds.len() {
			// Clear the previous events
			fds[idx].events = 0;
			// This is a writeable
			if 0 < idx & 0b01 {
				// and there's stuff to write
				if 0 < bufs[idx].filled {
					debug!("setting POLLOUT on {}", idx);
					fds[idx].events |= libc::POLLOUT;
				}
			}
			// Otherwise it's a readable
			else {
				// and there's room to read things
				if 0 < bufs[idx].remains(true) {
					debug!("setting POLLIN on {}", idx);
					fds[idx].events |= libc::POLLIN;
				}
			}
		}
	}
}
