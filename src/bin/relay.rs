#![allow(unused_variables, dead_code)]

use anyhow::Result;
use std::io::{Read, Write};

pub struct RelayNode<R: Read, W: Write> {
    pub readable: R,
    pub writeable: W,
}

// TODO call inner's read or write
// impl<R: Read, W: Write> Read for RelayNode<R, W> {}
// impl<R: Read, W: Write> Write for RelayNode<R, W> {}

pub fn relay<A: Read + Write, B: Read + Write>(node1: A, node2: B, key: &[u8; 32]) -> Result<()> {
    unimplemented!()
}
