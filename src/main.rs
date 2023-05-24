use aes_gcm::Aes256Gcm;
use base64::encode;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Error,
};
use chrono::NaiveDateTime;
use clap::{Parser, Subcommand, ValueEnum};
use config::Config;
use reqwest::blocking::Response;
use reqwest::header::HeaderMap;
use rpassword;
use serde::Deserialize;
use std::fmt;
use std::io::{self, BufRead};
use std::time::Duration;
use std::time::Instant;

use clap_duration::assign_duration_range_validator;
use duration_human::{DurationHuman, DurationHumanValidator};

assign_duration_range_validator!( EXPIRATION_RANGE = {default: 2h, min: 5min, max: 4day});

const URL_SAFE_ENGINE: base64::engine::fast_portable::FastPortable =
    base64::engine::fast_portable::FastPortable::from(
        &base64::alphabet::URL_SAFE,
        base64::engine::fast_portable::PAD,
    );

#[derive(Deserialize, Debug)]
struct CreateResponse {
    #[serde(rename = "expiresAt")]
    expires_at: i64,
}

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about,
    long_about = Some("Encrypts a secret and makes it available for sharing via one-time URL.

The secret is stored encrypted for a specified duration which can range
from 5 minutes to 4 days (default is 24 hours). The secret gets deleted
from the server upon retrieval therefore can only be viewed once.

"))]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    // Configuration file
    #[arg(short, long, default_value = "~/ots.yaml")]
    config: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create end-to-end encrypted secret
    New {
        #[arg(
            short,
            long,
            value_name = "DURATION",
            help = format!("The duration of the secret after which it will be deleted from the server. {}", EXPIRATION_RANGE),
            default_value = EXPIRATION_RANGE.default,
            value_parser = {|lifetime: &str|EXPIRATION_RANGE.parse_and_validate(lifetime)}
        )]
        expiration: DurationHuman,

        #[arg(
            short,
            long,
            default_value = Cipher::Aes256gcm.to_string(),
            help = "Cipher used for encryption"
        )]
        cipher: Cipher,

        #[arg(
            short = 's',
            long,
            help = "Read from stdin. Useful for reading files through unix pipes"
        )]
        read_from_stdin: bool,
    },
}

#[derive(
    Debug, Copy, Clone, serde_derive::Serialize, PartialEq, Eq, PartialOrd, Ord, ValueEnum,
)]
enum Cipher {
    /// AES 256 GCM
    Aes256gcm,
    ///  ChaCha20-Poly1305
    Chapoly,
}

impl fmt::Display for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Cipher::Aes256gcm => write!(f, "aes256gcm"),
            Cipher::Chapoly => write!(f, "chapoly"),
        }
    }
}

#[derive(Debug, Default, serde_derive::Deserialize, PartialEq, Eq)]
struct AppConfig {
    #[serde(rename = "apiUrl")]
    api_url: String,
}

fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::New {
            expiration,
            cipher,
            read_from_stdin,
        } => new(expiration, cipher, read_from_stdin),
    }
}

fn new(expiration: DurationHuman, cipher: Cipher, read_from_stdin: bool) {
    let duration = get_duration(expiration.into());
    let secret = read_secret(read_from_stdin);

    match encrypt(secret, cipher) {
        (Ok(ciphertext), nonce, key) => {
            let ciphertext_with_nonce: Vec<u8> = [nonce, ciphertext].concat();
            let encoded = encode(&ciphertext_with_nonce);
            let resp = send_to_backend(encoded, cipher, duration);
            let view_url = get_view_url(resp.headers());
            let json: CreateResponse = resp.json().unwrap();
            let url = create_url(view_url, key);
            let formatted = NaiveDateTime::from_timestamp_opt(json.expires_at, 0)
                .unwrap()
                .format("%Y-%m-%d %H:%M:%S");
            println!(
                "Your secret is now available on the below URL.

{url}

You should only share this URL with the intended recipient.

Please note that once retrieved, the secret will no longer
be available for viewing. If not viewed, the secret will
automatically expire at approximately {expires_at} UTC",
                url = url,
                expires_at = formatted
            );
        }

        (Err(err), _, _) => panic!("Could not encrypt secret: {:?}", err),
    };
}

fn read_secret(read_from_stdin: bool) -> String {
    if read_from_stdin {
        read_stdin().unwrap()
    } else {
        println!("");
        rpassword::prompt_password("Enter your secret: ").unwrap()
    }
}

fn read_stdin() -> io::Result<String> {
    let mut lines = io::stdin().lock().lines();
    let mut user_input = String::new();

    while let Some(line) = lines.next() {
        let last_input = line.unwrap();
        // stop reading
        if last_input.len() == 0 {
            break;
        }
        // add a new line once user_input starts storing user input
        if user_input.len() > 0 {
            user_input.push_str("\n");
        }
        // store user input
        user_input.push_str(&last_input);
    }
    Ok(user_input)
}

fn app_config() -> AppConfig {
    let home = shellexpand::tilde("~");
    let config_file = format!("{}/.ots.yaml", home);
    let settings = Config::builder()
        .add_source(config::File::with_name(&config_file))
        .add_source(
            config::Environment::with_prefix("OTS")
                .separator("_")
                .prefix_separator("_"),
        )
        .build()
        .unwrap();
    settings.try_deserialize().unwrap()
}

fn get_duration(expiration: DurationHuman) -> Duration {
    let now = Instant::now();
    let then = expiration + now;
    then - now
}

type EncryptionResult = (Result<Vec<u8>, Error>, Vec<u8>, Vec<u8>);

fn encrypt(secret: String, cipher: Cipher) -> EncryptionResult {
    match cipher {
        Cipher::Chapoly => encrypt_chapoly(secret),
        Cipher::Aes256gcm => encrypt_aes(secret),
    }
}

fn encrypt_chapoly(secret: String) -> EncryptionResult {
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, secret.as_ref());
    (ciphertext, nonce.to_vec(), key.to_vec())
}

fn encrypt_aes(secret: String) -> EncryptionResult {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, secret.as_ref());
    (ciphertext, nonce.to_vec(), key.to_vec())
}

fn send_to_backend(encrypted_secret: String, cipher: Cipher, expiration: Duration) -> Response {
    let app_config = app_config();
    let client = reqwest::blocking::Client::new();
    client
        .post(app_config.api_url)
        .json(&serde_json::json!({
            "encryptedBytes": encrypted_secret,
            "expiresIn": expiration.as_secs(),
            "cipher": cipher.to_string()
        }))
        .send()
        .unwrap()
}

fn get_view_url(headers: &HeaderMap) -> String {
    headers
        .get("X-View-Url")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

fn create_url(view_url: String, key: Vec<u8>) -> String {
    let encoded_key = base64::encode_engine(key, &URL_SAFE_ENGINE);
    format!("{}?ref=neots#{}", view_url, encoded_key)
}
