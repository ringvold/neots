use base64::{encode};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Error
};
use aes_gcm::{
    Aes256Gcm
};
use chrono::NaiveDateTime;
use clap::{Parser, Subcommand};
use config::Config;
use reqwest::blocking::Response;
use reqwest::header::HeaderMap;
use rpassword::read_password;
use serde::Deserialize;
use std::io::{Write};

const URL_SAFE_ENGINE: base64::engine::fast_portable::FastPortable =
    base64::engine::fast_portable::FastPortable::from(
        &base64::alphabet::URL_SAFE,
        base64::engine::fast_portable::PAD);

#[derive(Deserialize, Debug)]
struct CreateResponse {
    #[serde(rename = "expiresAt")]
    expires_at: i64,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = Some("Encrypts a secret and makes it available for sharing via one-time URL.

The secret is stored encrypted for a specified duration which can range
from 5 minutes to 7 days (default is 24 hours). The secret gets deleted
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

#[derive(Subcommand)]
#[derive(Debug)]
enum Commands {
    /// Create end-to-end encrypted secret
    New {
        /// The duration of the secret after which it will be deleted from the server. Supported units: s,m,h
        #[arg(short, value_name = "x", long, value_name = "DURATION", default_value = "24h0m0s")]
        expiration: Option<String>,
        /// Cipher used for encryption
        #[arg(short, value_name = "", long, value_name = "aes256gcm, chaploy", default_value = "aes256gcm")]
        cipher: Option<String>
    },
}

#[derive(Debug, Default, serde_derive::Deserialize, PartialEq, Eq)]
struct AppConfig {
    #[serde(rename = "apiUrl")]
    api_url: String,
}

fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::New { expiration, cipher } => new(expiration, cipher),
    }
}

fn new(_expiration: Option<String>, cipher: Option<String>) {
    let app_config = app_config();

    println!("");
    println!("Enter your secret:");

    std::io::stdout().flush().unwrap();
    let secret = read_password().unwrap();

    match encrypt(secret, cipher) {
        (Ok(ciphertext), nonce, key, cipher) => {
            // TODO: Might be a better way to concat
            let ciphertext2: Vec<u8> = nonce.into_iter().chain(ciphertext.into_iter()).collect();
            let encoded = encode(&ciphertext2);
            let resp = send_to_backend(app_config.api_url, encoded, cipher);
            let view_url = get_view_url(resp.headers());
            let json: CreateResponse = resp.json().unwrap();
            let url = create_url(view_url, key);
            // TODO: Timestamp seems to not be correct. Some timezone stuff probably.
            let formatted = NaiveDateTime::from_timestamp_opt(json.expires_at, 0).unwrap().format("%Y-%m-%d %H:%M:%S");
            println!("Your secret is now available on the below URL.

{url}

You should only share this URL with the intended recipient.

Please note that once retrieved, the secret will no longer
be available for viewing. If not viewed, the secret will
automatically expire at approximately {expires_at}",  url = url, expires_at = formatted);
        },

        (Err(err),_,_,_) => panic!("Could not encrypt secret: {:?}", err),
    };
}

fn app_config() -> AppConfig {
    let home = shellexpand::tilde("~");
    let config_file = format!("{}/.ots.yaml", home);
    let settings = Config::builder()
        .add_source(config::File::with_name(&config_file))
        .add_source(config::Environment::with_prefix("OTS").separator("_").prefix_separator("_"))
        .build()
        .unwrap();
    settings.try_deserialize().unwrap()
}

type EncryptionResult = (Result<Vec<u8>, Error>, Vec<u8>,Vec<u8>, String);

fn encrypt(secret: String, maybe_cipher: Option<String>) -> EncryptionResult {
    if let Some(cipher) = maybe_cipher {
        match cipher.as_ref() {
            "chapoly" => encrypt_chapoly(secret, cipher),
            "aes256gcm" => encrypt_aes(secret, cipher),
            _ => panic!("Unknown cipher {:?}", cipher),

        }
    }
    else {
        encrypt_aes(secret, "aes256gcm".to_string())
    }
}

fn encrypt_chapoly(secret: String, cipher_str: String) -> EncryptionResult {
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, secret.as_ref());
    (ciphertext, nonce.to_vec(), key.to_vec(), cipher_str)
}

fn encrypt_aes(secret: String, cipher_str: String) -> EncryptionResult {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, secret.as_ref());
    (ciphertext, nonce.to_vec(), key.to_vec(), cipher_str)
}

fn send_to_backend(api_url: String, encrypted_secret: String, cipher: String) -> Response {
    let client = reqwest::blocking::Client::new();
    client
        .post(api_url)
        .json(&serde_json::json!({
            "encryptedBytes": encrypted_secret,
            "expiresIn": 7200,
            "cipher": cipher
        }))
        .send()
        .unwrap()
}
fn get_view_url(headers: &HeaderMap) -> String {
    headers.get("X-View-Url").unwrap().to_str().unwrap().to_string()
}

fn create_url(view_url: String, key: Vec<u8>) -> String {
    let encoded_key = base64::encode_engine(key, &URL_SAFE_ENGINE);
    format!("{}?ref=neots#{}", view_url, encoded_key)
}
