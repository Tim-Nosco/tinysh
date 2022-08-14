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
const INTERNALBUF_META: usize = 2 + 12 + 16;
struct InternalBuf {
    pub buf: [u8; INTERNALBUF_MAX_SIZE],
    pub filled: usize,
}

impl InternalBuf {
    // After reading from buf, remove the used data
    fn clear(&mut self, amount: usize) {
        // Move data from self.buf[amount..filled] to self.buf[0..filled-amount]
        if amount < self.filled {
            let mut tmp = [0u8; INTERNALBUF_MAX_SIZE];
            tmp[0..self.filled - amount].copy_from_slice(&self.buf[amount..self.filled]);
            self.buf[..].copy_from_slice(&tmp[..]);
        }
        // Update the remaining data count
        self.filled = self.filled.saturating_sub(amount);
    }
    // Determine how large the next decrypted message would be
    fn next_decrypt_len(&self) -> Option<usize> {
        // First, check if there's a full message to decrypt
        if self.filled >= 2 {
            let enc_msg_size = u16::from_be_bytes(self.buf[0..2].try_into().ok()?).into();
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
    // Return a decrypted message from the interal buffer (and clear decrypted)
    fn decrypt(&mut self, cipher: &mut Aes256Gcm) -> Result<Vec<u8>> {
        // Check that there's a full message
        if let Some(dec_msg_size) = self.next_decrypt_len() {
            let nonce = Nonce::from_slice(&self.buf[2..2 + 12]);
            let pt = cipher
                .decrypt(nonce, &self.buf[2 + 12..INTERNALBUF_META + dec_msg_size])
                .or(Err(anyhow!("Unable to decrypt")));
            self.clear(INTERNALBUF_META + dec_msg_size);
            pt
        } else {
            Err(anyhow!("Not enough data to decrypt completely"))
        }
    }
    // Query how much space is left for new data
    fn remains(&self, raw: bool) -> usize {
        if raw {
            INTERNALBUF_MAX_SIZE.saturating_sub(self.filled)
        } else {
            // account for 2 byte size, 12 byte nonce, and 16 byte auth tag if encrypted
            INTERNALBUF_MAX_SIZE.saturating_sub(self.filled + INTERNALBUF_META)
        }
    }
    // Add data to the buffer, encrypting it first
    fn extend_encrypted<R>(&mut self, cipher: &mut Aes256Gcm, msg: &[u8], rng: &mut R) -> Result<()>
    where
        R: RngCore,
    {
        // Make a new nonce
        let mut nonce_raw = [0u8; 12];
        rng.try_fill_bytes(&mut nonce_raw)?;
        let nonce = Nonce::from_slice(&nonce_raw);
        // Encrypt the message
        let ct = cipher
            .encrypt(nonce, msg)
            .or(Err(anyhow!("Unable to encrypt.")))?;
        // Build the encrypted message onto self.buf:
        //  |--size--|--nonce--|--ciphertext--|
        //  size:
        let total_size: u16 = (2 + nonce.len() + ct.len()).try_into()?;
        self.buf[self.filled..self.filled + 2].copy_from_slice(&total_size.to_be_bytes());
        self.filled += 2;
        //  nonce:
        self.buf[self.filled..self.filled + nonce.len()].copy_from_slice(&nonce);
        self.filled += nonce.len();
        // ciphertext
        self.buf[self.filled..self.filled + ct.len()].copy_from_slice(&ct);
        self.filled += ct.len();
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
pub fn relay<A, B, R>(
    node1: &mut RelayNode<A, B>,
    node2: &mut TcpStream,
    key: &[u8; 32],
    rng: &mut R,
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
    let mut bufs = vec![
        InternalBuf::default(),
        InternalBuf::default(),
        InternalBuf::default(),
        InternalBuf::default(),
    ];

    // Initialize a cipher for each end of node2
    let mut ciphers = vec![
        Aes256Gcm::new_from_slice(key)?,
        Aes256Gcm::new_from_slice(key)?,
    ];

    loop {
        // Do the poll
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len().try_into()?, -1) } < 0 {
            Err(anyhow!("Error using poll."))?;
        }
        // println!("poll returns!");
        // Go through each event and recv or send as needed
        for (idx, fd) in fds.iter().enumerate() {
            // Lookup the working buffer
            let mut buf = &mut bufs[idx];
            // Ready to recv
            if 0 < (fd.revents & libc::POLLIN) {
                // println!("POLLIN on {}", idx);
                let max_recv = buf.remains(true);
                let this_node: &mut (dyn Read) = if 0 < (idx & 0b10) { node2 } else { node1 };
                let read_amt = this_node.read(&mut buf.buf[buf.filled..buf.filled + max_recv])?;
                if read_amt == 0 {
                    // socket shutdown
                    Err(anyhow!("Node shutdown."))?;
                }
                buf.filled += read_amt;
                // println!("filled: {}", buf.filled);
            }
            // Ready to send
            if 0 < (fd.revents & libc::POLLOUT) {
                // println!("POLLOUT on {}", idx);
                let this_node: &mut (dyn Write) = if 0 < (idx & 0b10) { node2 } else { node1 };
                buf.clear(this_node.write(&buf.buf[0..buf.filled])?);
                this_node.flush()?;
            }
        }

        // Encrypt / decrypt as needed
        // node1.writeable  <- D(c) <- node2.readable
        {
            let src = 0b10;
            let dst = 0b01;
            // while there's room to decrypt messages
            while let Some(decrypted_size) = bufs[src].next_decrypt_len() {
                // println!("decrypting");
                if decrypted_size > bufs[dst].remains(true) {
                    break;
                }
                let msg = bufs[src].decrypt(&mut ciphers[src >> 1])?;
                let filled = bufs[dst].filled;
                bufs[dst].buf[filled..filled + msg.len()].copy_from_slice(&msg);
                bufs[dst].filled += msg.len();
            }
        }
        // node1.readable   -> E(p) -> node2.writeable
        {
            let src = 0b00;
            let dst = 0b11;
            // calculate how much we can encrypt
            let mut max_msg_size = bufs[dst].remains(false);
            // account for block size
            max_msg_size -= max_msg_size % 16;
            // ensure we don't pull more than we have
            max_msg_size = max_msg_size.min(bufs[src].filled);
            if max_msg_size > 0 {
                // println!("encrypting");
                // Fill up the remaining space in dst with a new message
                // First we must do some trickery to get two mutable pointers in the bufs array
                let (part1, part2) = bufs.split_at_mut(2);
                let srcbuf = &mut part1[0];
                let dstbuf = &mut part2[1];
                // Next, extract out the message we want to encrypt
                let msg = &srcbuf.buf[0..max_msg_size];
                // Encrypt it
                dstbuf.extend_encrypted(&mut ciphers[src >> 1], &msg, rng)?;
                // Discard the used content
                srcbuf.clear(msg.len());
            }
        }

        // Set POLLIN and POLLOUT
        for idx in 0..fds.len() {
            // Clear the previous events
            fds[idx].events = 0;
            // This is a writeable
            if 0 < idx & 0b01 {
                // and there's stuff to write
                if 0 < bufs[idx].filled {
                    fds[idx].events |= libc::POLLOUT;
                }
            }
            // Otherwise it's a readable
            else {
                // and there's room to read things
                if 0 < bufs[idx].remains(true) {
                    fds[idx].events |= libc::POLLIN;
                }
            }
        }
    }
}
