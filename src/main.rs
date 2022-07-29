#![no_main]

use std::fs::File;
use std::io::Write;
use std::os::unix::io::FromRawFd;

use p256::{ecdh::EphemeralSecret, EncodedPoint, PublicKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn stdout() -> File {
    unsafe { File::from_raw_fd(1) }
}

#[no_mangle]
pub fn main(_argc: i32, _argv: *const *const u8) {
    let mut stdout = stdout();

    // let seed: u64 = unsafe { getauxval(AT_RANDOM) } as u64;
    let mut rng = ChaCha20Rng::seed_from_u64(0);

    let secret_a = EphemeralSecret::random(&mut rng);

    let pub_a = secret_a.public_key().to_string();
    stdout.write(pub_a.as_bytes()).unwrap();
}
