#![allow(unused_variables, dead_code)]
extern crate libc;

use anyhow::Result;
use std::io::{Error, Read, Write};
use std::net::TcpStream;
use std::os::unix::io::AsRawFd;

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

// Encrypted relay between two nodes
pub fn relay<A, B>(node1: RelayNode<A, B>, node2: &mut TcpStream, key: &[u8; 32]) -> Result<()>
where
    A: ReadFd,
    B: WriteFd,
{
    // Create an array of three fd events
    let mut fds = [libc::pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    }; 3];
    // Initialize the node1 & 2 file descriptors
    fds[0].fd = node1.readable.as_raw_fd();
    fds[1].fd = node1.writeable.as_raw_fd();
    fds[2].fd = (*node2).as_raw_fd();
    // Create a buffer for each node
    //
    unimplemented!()
}
