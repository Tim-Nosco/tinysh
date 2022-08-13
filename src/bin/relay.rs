#![allow(unused_variables, dead_code)]
extern crate libc;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use rand_core::{CryptoRng, RngCore};
use std::io::{Error, Read, Write};
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;

pub trait ReadWrite = Read + Write;
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

// This is an internal buffer for storage of encrypted and decrypted messages
//  Encrypted messages will have the following form:
//  |--size--|---E(msg)---|
//  where size is 2 bytes in network-byte-order
//  and E(msg) is the encrypted message including:
//      - the nonce (12 bytes)
//      - the data
//      - the authentication tag (16 bytes)
const INTERNALBUF_MAX_SIZE: usize = 1024;
#[derive(Clone, Copy)]
struct InternalBuf {
    pub buf: [u8; INTERNALBUF_MAX_SIZE],
    pub filled: usize,
}

impl InternalBuf {
    // After reading from buf, remove the used data
    fn clear(&mut self, amount: usize) {
        // Move data from self.buf[amount..filled] to self.buf[0..filled-amount]
        todo!();
        // Update the remaining data count
        self.filled.saturating_sub(amount);
    }
    // Use this to ensure a message is complete before decrypting
    fn msg_complete(&mut self) -> bool {
        todo!()
    }
    // Return a decrypted message from the interal buffer
    fn decrypt(&mut self, cipher: Aes256Gcm) -> Result<Vec<u8>> {
        todo!()
    }
    // Query how much space is left for new data
    fn remains(&mut self, raw: bool) -> usize {
        if raw {
            INTERNALBUF_MAX_SIZE.saturating_sub(self.filled)
        } else {
            // account for 2 byte size, 12 byte nonce, and 16 byte auth tag if encrypted
            INTERNALBUF_MAX_SIZE.saturating_sub(self.filled + 2 + 12 + 16)
        }
    }
    // Add data to the buffer, encrypting it first
    fn extend_encrypted(&mut self, cipher: Aes256Gcm, msg: &[u8]) -> Result<()> {
        todo!()
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
pub fn relay<A, B, R>(
    node1: &mut RelayNode<A, B>,
    node2: &mut TcpStream,
    key: &[u8; 32],
    rng: R,
) -> Result<()>
where
    A: ReadFd,
    B: WriteFd,
    R: CryptoRng + RngCore,
{
    // Create an array for fd events
    // 1 for side of the two duplexes
    let mut fds = [libc::pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    }; 4];

    // Initialize the node1 & 2 file descriptors
    fds[0b00].fd = node1.readable.as_raw_fd(); // Read
    fds[0b01].fd = node1.writeable.as_raw_fd(); // Write
    fds[0b10].fd = (*node2).as_raw_fd(); // Read
    fds[0b10].fd = (*node2).as_raw_fd(); // Write

    // Set initial events
    fds[0b00].events |= libc::POLLIN;
    fds[0b10].events |= libc::POLLIN;

    // Create a buffer for each fds entry
    let bufs = [InternalBuf::default(); 4];

    // Initialize a cipher for each end of node2
    let mut ciphers = vec![
        Aes256Gcm::new_from_slice(key),
        Aes256Gcm::new_from_slice(key),
    ];

    loop {
        // Do the poll
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len().try_into()?, -1) } < 0 {
            Err(anyhow!("Error using poll."))?;
        }
        // Go through each event and recv or send as needed
        for (idx, fd) in fds.iter().enumerate() {
            // Lookup the working buffer
            let mut buf = bufs[idx];
            // Ready to recv
            if 0 < (fd.revents & libc::POLLIN) {
                let max_recv = buf.remains(true);
                let this_node: &mut (dyn Read) = if 0 < (idx & 0b10) { node2 } else { node1 };
                buf.filled += this_node.read(&mut buf.buf[buf.filled..buf.filled + max_recv])?;
            }
            // Ready to send
            if 0 < (fd.revents & libc::POLLOUT) {
                let this_node: &mut (dyn Write) = if 0 < (idx & 0b10) { node2 } else { node1 };
                buf.clear(this_node.write(&buf.buf[0..buf.filled])?);
            }
        }
        // TODO: Encrypt / decrypt as needed
        // TODO: Set POLLIN and POLLOUT
        unimplemented!()
    }
}
