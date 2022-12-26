use base64::{encode};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Error
};
use chrono::NaiveDateTime;
use clap::{Parser, Subcommand};
use config::Config;
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
        /// The duration of the secret after which it will be deleted from the server. Supported units: s,m,h (default 24h0m0s)
        #[arg(short, value_name = "x", long, value_name = "DURATION", default_value = "14h")]
        expiration: Option<String>
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
        Commands::New { expiration } => new(expiration),
    }
}

fn new(_expiration: Option<String>) {
    let app_config = app_config();

    println!("");
    println!("Enter your secret:");

    std::io::stdout().flush().unwrap();
    let secret = read_password().unwrap();
    match encrypt(secret) {
        (Ok(ciphertext), nonce, key) => {
            // TODO: Might be a better way to concat
            let ciphertext2: Vec<u8> = nonce.into_iter().chain(ciphertext.into_iter()).collect();
            let encoded = encode(&ciphertext2);
            let client = reqwest::blocking::Client::new();
            let resp = client
                .post(app_config.api_url)
                .json(&serde_json::json!({
                    "encryptedBytes": encoded,
                    "expiresIn": 7200,
                    "cipher": "chapoly"
                }))
                .send()
                .unwrap();
            let view_url = resp.headers().get("X-View-Url").unwrap().to_str().unwrap().to_string();
            let json: CreateResponse = resp.json()
                .unwrap();
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
        (Err(err),_,_) => panic!("{:?}", err),
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
fn encrypt(secret: String) -> (Result<Vec<u8>, Error>, Vec<u8>,Vec<u8>) {
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
    (cipher.encrypt(&nonce, secret.as_ref()), nonce.to_vec(), key.to_vec())
}

fn create_url(view_url: String, key: Vec<u8>) -> String {
    let encoded_key = base64::encode_engine(key, &URL_SAFE_ENGINE);
    format!("{}?ref=neots#{}", view_url, encoded_key)
}
