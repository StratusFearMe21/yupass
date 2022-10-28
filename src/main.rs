use anyhow::{bail, ensure, Context};
use const_colors::{bold, end, red};
use crypto_box::{
    aead::{Aead, AeadCore},
    PublicKey, SecretKey,
};
use rand_core::OsRng;
use reqwest::StatusCode;
use std::{
    borrow::Borrow,
    collections::HashMap,
    io::{Read, Write},
    ops::Deref,
    process::{Command, Stdio},
};

#[cfg(not(windows))]
use copypasta_ext::prelude::ClipboardProvider;

use enigo::KeyboardControllable;

use gpgme::{Key, Protocol};

use serde::{Deserialize, Serialize};
use structopt::StructOpt;
use yubico_manager::{
    config::{Config, Mode, Slot},
    Yubico,
};

const ENTAB: [char; 91] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '!', '#', '$', '%', '&', '(', ')', '*', '+', ',', '.', '/', ':', ';',
    '<', '=', '>', '?', '@', '[', ']', '^', '_', '`', '{', '|', '}', '~', '"',
];

macro_rules! server_keybox {
    ($a:expr) => {
        crypto_box::ChaChaBox::new(
            &PublicKey::from($a.server_public.context("No server public key")?),
            &SecretKey::from($a.client_private.context("No client private key")?),
        )
    };
}

#[derive(Serialize, Deserialize)]
struct ServerMessage {
    message: Vec<u8>,
    nonce: [u8; 24],
}

#[derive(Serialize, Deserialize, StructOpt)]
struct PasswordOpts {
    /// Usesrname of the account in question
    username: String,
    /// Whether or not to remove symbols from passwords
    #[structopt(short)]
    no_symbols: bool,
    /// Number of iterations to give password
    #[structopt(short, default_value = "5")]
    length: u8,
    /// Notes about the given password
    #[structopt(long)]
    notes: Option<String>,
    /// Cut the password to a certain length
    #[structopt(short)]
    cut: Option<usize>,
}

#[derive(Serialize)]
struct BitwardenJson {
    items: Vec<BitwardenItem>,
}

#[derive(Serialize)]
struct BitwardenItem {
    #[serde(rename = "type")]
    _type: u8,
    name: String,
    login: BitwardenLogin,
}

#[derive(Serialize)]
struct BitwardenLogin {
    username: String,
    password: String,
}

impl PasswordOpts {
    fn print_opts(&self) {
        println!(
            concat!(
                bold!(),
                "---------",
                end!(),
                "\nUsername: {}\n{}\n{}Length: {}{}\n{}\n{}\n",
                bold!(),
                "---------",
                end!()
            ),
            self.username,
            if self.no_symbols {
                concat!(bold!(), "No Symbols: true", end!())
            } else {
                "No Symbols: false"
            },
            if self.length != 5 { bold!() } else { "" },
            self.length,
            if self.length != 5 { end!() } else { "" },
            if let Some(notes) = &self.notes {
                format!(concat!(bold!(), "Notes: {}", end!()), notes)
            } else {
                "Notes: None".to_string()
            },
            if let Some(cut) = &self.cut {
                format!(concat!(bold!(), "Cut: {}", end!()), cut)
            } else {
                "Cut: None".to_string()
            }
        );
    }
}

#[derive(Serialize, Deserialize, StructOpt)]
struct YuPassOpts {
    /// If using a syncing server, which one to use
    #[structopt(short)]
    server: Option<String>,
    key: String,
    #[structopt(skip)]
    rev: u32,
    #[structopt(skip)]
    client_private: Option<[u8; 32]>,
    #[structopt(skip)]
    server_public: Option<[u8; 32]>,
}

impl YuPassOpts {
    fn print_opts(&self, server_status: &str) {
        println!(
            concat!(
                bold!(),
                "---------",
                end!(),
                "\nKey: {}\n",
                bold!(),
                "{}",
                end!(),
                "\n",
                bold!(),
                "---------",
                end!()
            ),
            self.key, server_status,
        );
    }
}

#[derive(StructOpt)]
#[structopt(name = "YuPass", about = "A password manager, powered by the YubiKey")]
enum Opts {
    /// Initialize the password database
    Init {
        /// GPG key to encrypt passwords with
        #[structopt(flatten)]
        opts: YuPassOpts,
    },
    /// Sync passwords from a sync server
    Sync {
        /// GPG key to encrypt passwords with
        #[structopt(flatten)]
        opts: YuPassOpts,
        server_public: std::path::PathBuf,
        client_private: std::path::PathBuf,
    },
    /// Get a password using DMenu
    Get {
        /// Get the options for a specific password
        password: Option<String>,
    },
    /// Get the notes of a given password
    Notes {
        /// The title of the password you want to look up
        title: String,
    },
    /// Add or edit a password
    Add {
        /// The title of the account in question
        title: String,
        /// Password of the account in question
        #[structopt(flatten)]
        password: PasswordOpts,
    },
    /// Remove a password
    Remove {
        /// The title of the password you want to remove
        title: String,
    },
    /// Export the keyfile
    ExportKeyfile,
    /// Export to Bitwarden
    Export,
}

fn main() -> anyhow::Result<()> {
    match Opts::from_args() {
        Opts::Init { mut opts } => {
            opts.rev = 1;
            if opts.server.is_some() {
                let key = SecretKey::generate(&mut OsRng);
                opts.client_private = Some(key.to_bytes());
                let init_request = reqwest::blocking::Client::new()
                    .post(format!(
                        "{}/init",
                        opts.server.as_ref().context("Cannot find server URL")?
                    ))
                    .body(key.public_key().as_bytes().to_vec())
                    .send()?;
                if init_request.status() == StatusCode::FORBIDDEN {
                    opts.print_opts(
                        concat!(red!(), "Server: Server initialization failed, server already initialized. Follow these steps to get the other computer working\n\n1. run \"yupass export-keyfile\" to write the keyfile you need to the disk\n2. Put the keyfile on the other compter you want to sync\n3. run \"yupass sync\" with the keyfile as your argument to begin syncing passwords between computers"));
                } else if init_request.status() == StatusCode::OK {
                    opts.print_opts(
                        opts.server
                            .as_ref()
                            .context("Could not get server URL")?
                            .borrow(),
                    );
                }
                opts.server_public = Some(pubkey_slice(init_request.bytes()?.borrow()))
            } else {
                opts.print_opts("None");
            }
            std::fs::write(
                format!(
                    "{}/.yupassopts",
                    dirs::home_dir()
                        .context("Cannot find home directory")?
                        .display()
                ),
                bincode::serialize(&opts)?,
            )?;
            encrypt_passwords(HashMap::new(), opts)?;
        }
        Opts::Sync {
            mut opts,
            server_public,
            client_private,
        } => {
            opts.client_private = Some(pubkey_slice(std::fs::read(client_private)?.as_slice()));
            opts.server_public = Some(pubkey_slice(std::fs::read(server_public)?.as_slice()));
            std::fs::write(
                format!(
                    "{}/.yupassopts",
                    dirs::home_dir()
                        .context("Cannot find home directory")?
                        .display()
                ),
                bincode::serialize(&opts)?,
            )?;
            ensure!(opts.server.is_some(), "You did not provide a server URL");
            get_passwords()?;
        }
        Opts::Get { password } => {
            let passwords = get_passwords()?;
            if let Some(pass) = password {
                passwords
                    .get(&pass)
                    .context("Couldn't find that password in the database")?
                    .print_opts();
                return Ok(());
            }
            let mut yubi = Yubico::new();
            let device = yubi.find_yubikey()?;
            let passproc = Command::new("tofi")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()?;
            passproc
                .stdin
                .context("Cannot get stdin of dmenu")?
                .write_all(
                    passwords
                        .keys()
                        .into_iter()
                        .map(|f| format!("{}\n", f))
                        .collect::<String>()
                        .as_bytes(),
                )?;
            let mut passopt = String::new();
            passproc
                .stdout
                .context("Cannot get stout of dmenu")?
                .read_to_string(&mut passopt)?;
            let passstruct = passwords
                .get(passopt.trim())
                .context("Couldn't find that password in the database")?;

            let hmac_result = yubi
                .challenge_response_hmac(
                    passopt.as_bytes(),
                    Config::default()
                        .set_vendor_id(device.vendor_id)
                        .set_product_id(device.product_id)
                        .set_variable_size(true)
                        .set_mode(Mode::Sha1)
                        .set_slot(Slot::Slot2),
                )
                .context("HMAC Failed")?;

            let mut ctx = copypasta_ext::wayland_bin::ClipboardContext::new().unwrap();
            ctx.set_contents(encode_password(
                hmac_result.deref(),
                passstruct.length,
                passstruct.cut,
                passstruct.no_symbols,
            )?)
            .unwrap();

            std::io::stdin().read_line(&mut String::new());

            ctx.set_contents(passstruct.username.to_owned()).unwrap();

            std::io::stdin().read_line(&mut String::new());
        }
        Opts::Notes { title } => {
            println!(
                "{}",
                get_passwords()?
                    .get(&title)
                    .context("Couldn't find that password in the database")?
                    .notes
                    .clone()
                    .context("No notes")?
            )
        }
        Opts::Add { title, password } => {
            password.print_opts();
            let mut passwords = get_passwords()?;
            passwords.insert(title, password);
            encrypt_passwords(
                passwords,
                bincode::deserialize(
                    std::fs::read(format!(
                        "{}/.yupassopts",
                        dirs::home_dir()
                            .context("Cannot find home directory")?
                            .display()
                    ))?
                    .as_slice(),
                )?,
            )?
        }
        Opts::Remove { title } => {
            let mut passwords = get_passwords()?;
            passwords
                .remove(&title)
                .context("Couldn't find that password in the database")?;
            encrypt_passwords(
                passwords,
                bincode::deserialize(
                    std::fs::read(format!(
                        "{}/.yupassopts",
                        dirs::home_dir()
                            .context("Cannot find home directory")?
                            .display()
                    ))?
                    .as_slice(),
                )?,
            )?
        }
        Opts::ExportKeyfile => {
            std::fs::write(
                "client_private",
                bincode::deserialize::<YuPassOpts>(
                    std::fs::read(format!(
                        "{}/.yupassopts",
                        dirs::home_dir()
                            .context("Cannot find home directory")?
                            .display()
                    ))?
                    .as_slice(),
                )?
                .client_private
                .context("Cannot find the server keyfile")?,
            )?;
            std::fs::write(
                "server_public",
                bincode::deserialize::<YuPassOpts>(
                    std::fs::read(format!(
                        "{}/.yupassopts",
                        dirs::home_dir()
                            .context("Cannot find home directory")?
                            .display()
                    ))?
                    .as_slice(),
                )?
                .server_public
                .context("Cannot find the server keyfile")?,
            )?;
        }
        Opts::Export => {
            let passwords = get_passwords()?;
            let mut items = BitwardenJson { items: Vec::new() };
            for (mut key, value) in passwords.into_iter() {
                let mut yubi = Yubico::new();
                let device = yubi.find_yubikey()?;
                key.push('\n');
                let hmac_result = yubi
                    .challenge_response_hmac(
                        key.as_bytes(),
                        Config::default()
                            .set_vendor_id(device.vendor_id)
                            .set_product_id(device.product_id)
                            .set_variable_size(true)
                            .set_mode(Mode::Sha1)
                            .set_slot(Slot::Slot2),
                    )
                    .context("HMAC Failed")?;
                let password = encode_password(
                    hmac_result.deref(),
                    value.length,
                    value.cut,
                    value.no_symbols,
                )?;
                items.items.push(BitwardenItem {
                    _type: 1,
                    name: key,
                    login: BitwardenLogin {
                        username: value.username,
                        password,
                    },
                });
            }
            serde_json::to_writer(std::fs::File::create("export.json").unwrap(), &items).unwrap();
        }
    }
    Ok(())
}

fn get_passwords() -> anyhow::Result<HashMap<String, PasswordOpts>> {
    let mut opts: YuPassOpts = bincode::deserialize(
        std::fs::read(format!(
            "{}/.yupassopts",
            dirs::home_dir()
                .context("Cannot find the server keyfile")?
                .display()
        ))?
        .as_slice(),
    )?;
    let mut input;
    match &opts.server {
        Some(server) => {
            let keybox = server_keybox!(opts);
            let rev: u32 = String::from_utf8(decrypt_message(
                reqwest::blocking::Client::new()
                    .post(format!("{}/request", server))
                    .body(encrypt_message(b"rev", &keybox)?)
                    .send()?
                    .bytes()?
                    .borrow(),
                &keybox,
            )?)?
            .parse()?;
            if opts.rev != rev {
                let pgp = decrypt_message(
                    reqwest::blocking::Client::new()
                        .post(format!("{}/request", server))
                        .body(encrypt_message(b"file", &keybox)?)
                        .send()?
                        .bytes()?
                        .borrow(),
                    &keybox,
                )?;
                std::fs::write(
                    format!(
                        "{}/.yupass.asc",
                        dirs::home_dir()
                            .context("Cannot find home directory")?
                            .display()
                    ),
                    &pgp,
                )?;
                opts.rev = rev;
                std::fs::write(
                    format!(
                        "{}/.yupassopts",
                        dirs::home_dir()
                            .context("Cannot find home directory")?
                            .display()
                    ),
                    bincode::serialize(&opts)?,
                )?;
                input = pgp;
            } else {
                input = std::fs::read_to_string(format!(
                    "{}/.yupass.asc",
                    dirs::home_dir()
                        .context("Cannot find home directory")?
                        .display()
                ))?
                .as_bytes()
                .to_vec();
            }
        }
        None => {
            input = std::fs::read_to_string(format!(
                "{}/.yupass.asc",
                dirs::home_dir()
                    .context("Cannot find home directory")?
                    .display()
            ))?
            .as_bytes()
            .to_vec()
        }
    }
    let mut ctx = gpgme::Context::from_protocol(Protocol::OpenPgp)?;
    ctx.set_armor(true);
    let mut outbuf = Vec::new();
    ctx.decrypt(&mut input, &mut outbuf)?;
    Ok(bincode::deserialize(outbuf.as_slice())?)
}

fn encrypt_passwords(
    passwords: HashMap<String, PasswordOpts>,
    opts: YuPassOpts,
) -> anyhow::Result<()> {
    let mut output = Vec::new();
    let mut ctx = gpgme::Context::from_protocol(Protocol::OpenPgp)?;
    ctx.set_armor(true);
    let keys = ctx
        .find_keys(vec![opts.key])?
        .filter_map(|x| x.ok())
        .collect::<Vec<Key>>();
    ctx.encrypt(&keys, bincode::serialize(&passwords)?, &mut output)?;
    std::fs::write(
        format!(
            "{}/.yupass.asc",
            dirs::home_dir()
                .context("Cannot find home directory")?
                .display()
        ),
        &output,
    )?;
    if let Some(server) = &opts.server {
        let keybox = server_keybox!(opts);
        let code = reqwest::blocking::Client::new()
            .post(format!("{}/upload", server))
            .body(encrypt_message(output.as_slice(), &keybox)?)
            .send()?
            .status();

        if code == StatusCode::FORBIDDEN {
            bail!("Invalid signature, cannot modify password database");
        }
    }
    Ok(())
}

// Code stolen (borrowed ;) ) from base91 crate
fn encode_password(
    to_encode: &[u8],
    length: u8,
    cut: Option<usize>,
    no_symbols: bool,
) -> anyhow::Result<String> {
    let mut final_result = String::new();

    if !no_symbols {
        let mut key: u32;
        let mut rem: u32 = 0;
        let mut shift: u32 = 0;

        for _ in 0..length {
            for c in to_encode {
                rem |= (c.to_owned() as u32) << shift;
                shift += 8;

                if shift > 13 {
                    key = rem & 8191;

                    if key > 88 {
                        rem >>= 13;
                        shift -= 13;
                    } else {
                        key = rem & 16383;
                        rem >>= 14;
                        shift -= 14;
                    }

                    final_result.push(ENTAB[(key % 91) as usize]);
                    final_result.push(ENTAB[(key / 91) as usize]);
                }
            }
        }
    } else {
        final_result = base64::encode(to_encode);
    }

    if let Some(cutsome) = cut {
        final_result.truncate(cutsome);
    }

    Ok(final_result)
}

fn pubkey_slice(s: &[u8]) -> [u8; 32] {
    let mut a: [u8; 32] = Default::default();
    a.copy_from_slice(s);
    a
}

fn encrypt_message(message: &[u8], keybox: &crypto_box::ChaChaBox) -> anyhow::Result<Vec<u8>> {
    let nonce = crypto_box::ChaChaBox::generate_nonce(&mut OsRng);
    Ok(bincode::serialize(&ServerMessage {
        nonce: nonce.into(),
        message: keybox.encrypt(&nonce, message).unwrap(),
    })?)
}

fn decrypt_message(message: &[u8], keybox: &crypto_box::ChaChaBox) -> anyhow::Result<Vec<u8>> {
    let des_message: ServerMessage = bincode::deserialize(message)?;
    Ok(keybox.decrypt(&des_message.nonce.into(), des_message.message.as_slice())?)
}
