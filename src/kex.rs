#![allow(dead_code)]

use crate::util::debug;
use anyhow::anyhow;
use base64ct::{Base64, Encoding};
use p256::ecdh::{diffie_hellman, EphemeralSecret};
use p256::ecdsa::{
	signature::{Signature, Signer, Verifier},
	SigningKey, VerifyingKey,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha2::Sha256;
use std::io::{Read, Write};
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KexError {
	#[error("play_dh_kex error")]
	KeyDecode,
	#[error("write error")]
	Write,
	#[error("calc shared secret")]
	CalcSharedSecret,
}

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

const ENCODED_SEC1_LEN: usize = 512;
const PUB_SIZE_FIELD: usize = 8;
const ARCH_SIZE: usize = std::mem::size_of::<usize>();

// Conduct the ECDH key exchange on remote
pub fn play_dh_kex_remote<A: Write>(
	writeable: &mut A,
	pub_l: &PublicKey,
	seed: Option<u64>,
) -> Result<[u8; 32], KexError> {
	// Generate remote's keys
	let secret_r = gen_key(seed);
	let mut pub_r_fixed_size = [0u8; ENCODED_SEC1_LEN];
	let pub_r = secret_r.public_key().to_encoded_point(true);
	let size_size = PUB_SIZE_FIELD;
	pub_r_fixed_size[size_size - ARCH_SIZE..size_size]
		.copy_from_slice(&pub_r.as_bytes().len().to_be_bytes());
	pub_r_fixed_size[size_size..size_size + pub_r.as_bytes().len()]
		.copy_from_slice(&pub_r.as_bytes());
	// Send public key to local
	writeable
		.write(&pub_r_fixed_size)
		.or(Err(KexError::Write))?;

	// Calculate the shared secret
	let secret_hkdf =
		secret_r.diffie_hellman(&pub_l).extract::<Sha256>(None);
	let mut key = [0u8; 32];
	secret_hkdf
		.expand(&vec![0u8; 0], &mut key)
		.or(Err(KexError::CalcSharedSecret))?;
	todo!();
	Ok(key)
}

// Conduct ECDH key exchange on local
pub fn play_dh_kex_local<T: Read + Write>(
	sock: &mut T,
	secret_l: &SecretKey,
) -> anyhow::Result<[u8; 32]> {
	// Accept the other side's public key
	let mut other_pub = [0u8; ENCODED_SEC1_LEN];
	sock.read_exact(&mut other_pub)?;
	// Parse for the pubkey size
	let size_size = PUB_SIZE_FIELD;
	let mut pub_size_bytes = [0u8; ARCH_SIZE];
	pub_size_bytes.copy_from_slice(
		&other_pub[size_size - ARCH_SIZE..size_size],
	);
	let pub_size = usize::from_be_bytes(pub_size_bytes);
	// Parse the pubkey
	let pub_r = PublicKey::from_sec1_bytes(
		&other_pub[size_size..size_size + pub_size],
	)?;
	debug!("Got remote's pub key:\n{:#}", pub_r.to_string());
	// Calculate the shared secret
	let secret_hkdf = diffie_hellman(
		secret_l.to_nonzero_scalar(),
		pub_r.as_affine(),
	)
	.extract::<Sha256>(None);
	let mut key = [0u8; 32];
	secret_hkdf
		.expand(&vec![0u8; 0], &mut key)
		.or(Err(anyhow!("Unable to expand shared secret")))?;
	Ok(key)
}

// Send a challenge to ensure the local can use the expected private
// key
pub fn play_auth_challenge_remote<
	T: RngCore + CryptoRng,
	A: Write + Read,
>(
	sock: &mut A,
	pub_l: &PublicKey,
	rng: &mut T,
) -> anyhow::Result<()> {
	// send the challenge
	let mut challenge = [0u8; 128];
	rng.try_fill_bytes(&mut challenge)?;
	debug!("Created challenge:\n{:02X?}\n", challenge);
	sock.write(&challenge)?;

	// recv the signed challenge
	let mut signature_raw = [0u8; 64];
	sock.read_exact(&mut signature_raw)?;
	let signature = Signature::from_bytes(&signature_raw)?;
	debug!("Recv'd local's signature:\n{:#}\n", signature);

	// verify
	VerifyingKey::from(pub_l).verify(&challenge, &signature)?;
	Ok(())
}

// Sign challenge to authenticate
pub fn play_auth_challenge_local<A: Write + Read>(
	sock: &mut A,
	secret_l: &SecretKey,
) -> anyhow::Result<()> {
	// recv the challenge
	let mut challenge = [0u8; 128];
	sock.read_exact(&mut challenge)?;
	debug!("Recv'd remote's challenge:\n{:02X?}", challenge);

	// sign the challenge
	let signed_chal = SigningKey::from(secret_l).sign(&challenge);
	let signed_chal_b = signed_chal.as_bytes();
	debug!(
		"Generated signature of {} bytes:\n{:#}",
		signed_chal_b.len(),
		signed_chal
	);
	// debug!(
	//     "{:?}",
	//     VerifyingKey::from(secret_l.public_key()).verify(&
	// challenge, &signed_chal) );
	sock.write(&signed_chal_b)?;
	Ok(())
}
