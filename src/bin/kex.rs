#![allow(unused_variables, dead_code, unused_imports)]

use anyhow::{anyhow, Result};
use p256::ecdh::EphemeralSecret;
use p256::ecdsa::{signature::Verifier, VerifyingKey};
use p256::{PublicKey, SecretKey};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha2::Sha256;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::str::FromStr;

#[allow(unused_imports)]
use crate::STDOUT;

pub fn gen_key(seed: Option<u64>) -> EphemeralSecret {
    let rng = if let Some(imd) = seed {
        // use the seed
        ChaCha20Rng::seed_from_u64(imd)
    } else {
        // seed is not available, use /dev/urandom
        ChaCha20Rng::from_entropy()
    };
    EphemeralSecret::random(rng)
}

// Conduct the ECDH key exchange
pub fn play_dh_kex_remote<A: Write>(
    writeable: &mut A,
    pub_b: &PublicKey,
    seed: Option<u64>,
) -> Result<[u8; 32]> {
    // Generate local keys
    let secret_a = gen_key(seed);
    let pub_a = secret_a.public_key().to_string();
    let pub_a_fixed_size = format!("{:1$}", pub_a, 512);
    writeable.write(pub_a_fixed_size.as_bytes())?;

    // Calculate the shared secret
    let secret_hkdf = secret_a.diffie_hellman(&pub_b).extract::<Sha256>(None);
    let mut key = [0u8; 32];
    secret_hkdf
        .expand(&vec![0u8; 0], &mut key)
        .or(Err(anyhow!("Unable to expand shared secret")))?;
    Ok(key)
}

pub fn play_dh_kex_local<T: Read + Write>(sock: &mut T, key: &SecretKey) -> Result<[u8; 32]> {
    // Accept the other side's public key
    let mut other_pub = [0u8; 512];
    sock.read_exact(&mut other_pub)?;
    let pub_a = PublicKey::from_str(std::str::from_utf8(&other_pub)?.trim())?;
    println!("Got remote's pub key:\n{:#}", pub_a.to_string());
    // Setup the shared secret
    unimplemented!()
}

// Send a challenge to ensure the local can use the expected private key
#[allow(unused_variables)]
pub fn play_auth_challenge_remote<T: RngCore + CryptoRng, A: Write + Read>(
    sock: &mut A,
    key: &PublicKey,
    rng: &mut T,
) -> Result<()> {
    // send the challenge
    let mut challenge = [0u8; 128];
    rng.try_fill_bytes(&mut challenge)?;
    sock.write(&challenge)?;
    // recv the signed challenge

    unimplemented!()
}

// Sign challenge to authenticate
pub fn play_auth_challenge_local<A: Write + Read>(sock: &mut A, key: &SecretKey) -> Result<()> {
    // recv the challenge
    let mut challenge = [0u8; 128];
    sock.read_exact(&mut challenge)?;
    println!("recv'd challenge {:?}", challenge);

    unimplemented!()
}

// The ecdh library expects the PEM in a certain format
//  use this function to convert from straight b64 to
//  the expected format.
fn format_public_key(b64_pem: &str) -> String {
    // add a newline after each 64 chars
    let nl_sep_pem = b64_pem
        .chars()
        .enumerate()
        .fold(String::new(), |acc, (i, c)| {
            if i == 64 {
                format!("{}\n{}", acc, c)
            } else {
                format!("{}{}", acc, c)
            }
        });
    // add the beginning and end
    format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
        nl_sep_pem
    )
}

// Get remote's info from argv
pub fn get_local_info(argv: Vec<String>) -> Result<(IpAddr, PublicKey)> {
    if argv.len() < 3 {
        return Err(anyhow!("Expecting 2 arguments"));
    }
    // Parse the IP
    let ip = argv[1].parse()?;
    // Parse the public key which should just be the base64 component on a single line
    let pubkey = PublicKey::from_str(&format_public_key(&argv[2]))?;
    Ok((ip, pubkey))
}
