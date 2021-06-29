use anyhow::{bail, ensure, Context};
use console::{style, StyledObject};
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

use ed25519_dalek::{Keypair, Signature, Signer};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use structopt::StructOpt;
use yubico_manager::{
    config::{Config, Mode, Slot},
    Yubico,
};

macro_rules! server_message {
    ($a:expr, $b:expr) => {
        bincode::serialize(&ServerMessage {
            message: $a.to_vec(),
            signature: $b
                .server_keyfile
                .as_ref()
                .context("Server key file")?
                .sign($a),
        })?
    };
}

const ENTAB: [char; 91] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '!', '#', '$', '%', '&', '(', ')', '*', '+', ',', '.', '/', ':', ';',
    '<', '=', '>', '?', '@', '[', ']', '^', '_', '`', '{', '|', '}', '~', '"',
];

#[derive(Serialize)]
struct ServerMessage {
    message: Vec<u8>,
    signature: Signature,
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

impl PasswordOpts {
    fn print_opts(&self) {
        println!("{}", style("---------").bold());
        println!("Username: {}", self.username);
        println!(
            "{}",
            if self.no_symbols {
                style("No Symbols: true").bold()
            } else {
                style("No Symbols: false")
            }
        );
        println!(
            "{}",
            if self.length != 5 {
                style(format!("Length: {}", self.length)).bold()
            } else {
                style(format!("Length: {}", self.length))
            }
        );
        println!(
            "{}",
            if let Some(notes) = &self.notes {
                style(format!("Notes: {}", notes)).bold()
            } else {
                style("Notes: None".to_string())
            }
        );
        println!(
            "{}",
            if let Some(cut) = self.cut {
                style(format!("Cut: {}", cut)).bold()
            } else {
                style("Cut: None".to_string())
            }
        );
        println!("{}", style("---------").bold());
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
    server_keyfile: Option<Keypair>,
}

impl YuPassOpts {
    fn print_opts(&self, server_status: StyledObject<&str>) {
        println!("{}", style("---------").bold());
        println!("Key: {}", self.key);
        println!("{}", server_status);
        println!("{}", style("---------").bold());
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
        keyfile: std::path::PathBuf,
    },
    /// Get a password using DMenu
    Get,
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
}

fn main() -> anyhow::Result<()> {
    match Opts::from_args() {
        Opts::Init { mut opts } => {
            opts.rev = 1;
            if opts.server.is_some() {
                if std::path::Path::new("yupass_keyfile").exists() {
                    opts.server_keyfile = Some(Keypair::from_bytes(
                        std::fs::read("yupass_keyfile")?.as_slice(),
                    )?);
                } else {
                    opts.server_keyfile = Some(Keypair::generate(&mut OsRng {}));
                }
                let code = reqwest::blocking::Client::new()
                    .post(format!(
                        "{}/init",
                        opts.server.as_ref().context("Cannot find server URL")?
                    ))
                    .body(
                        opts.server_keyfile
                            .as_ref()
                            .context("Cannot find keyfile")?
                            .public
                            .to_bytes()
                            .to_vec(),
                    )
                    .send()?
                    .status();
                if code == StatusCode::FORBIDDEN {
                    opts.print_opts(
                        style("Server: Server initialization failed, server already initialized. Follow these steps to get the other computer working\n\n1. run \"yupass export-keyfile\" to write the keyfile you need to the disk\n2. Put the keyfile on the other compter you want to sync\n3. run \"yupass sync\" with the keyfile as your argument to begin syncing passwords between computers")
                        .red(),
                        );
                } else if code == StatusCode::OK {
                    opts.print_opts(
                        style(
                            opts.server
                                .as_ref()
                                .context("Could not get server URL")?
                                .borrow(),
                        )
                        .bold(),
                    );
                }
            } else {
                opts.print_opts(style("None"));
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
        Opts::Sync { mut opts, keyfile } => {
            opts.server_keyfile = Some(Keypair::from_bytes(std::fs::read(keyfile)?.as_slice())?);
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
            let code = reqwest::blocking::Client::new()
                .post(format!(
                    "{}/request",
                    opts.server.as_ref().context("Cannot find server URL")?
                ))
                .body(server_message!(b"rev", opts))
                .send()?
                .status();
            if code == StatusCode::INTERNAL_SERVER_ERROR {
                bail!("Server has not been initialized");
            } else if code == StatusCode::FORBIDDEN {
                bail!("Signature invalid");
            }
            get_passwords()?;
        }
        Opts::Get => {
            let passwords = get_passwords()?;
            let mut yubi = Yubico::new();
            let device = yubi.find_yubikey()?;
            let passproc = Command::new("dmenu")
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

            let mut keyboard = enigo::Enigo::new();

            let hmac_result = yubi.challenge_response_hmac(
                passopt.as_bytes(),
                Config::default()
                    .set_vendor_id(device.vendor_id)
                    .set_product_id(device.product_id)
                    .set_variable_size(true)
                    .set_mode(Mode::Sha1)
                    .set_slot(Slot::Slot2),
            )?;

            let mut ctx = copypasta_ext::x11_fork::ClipboardContext::new().unwrap();
            ctx.set_contents(encode_password(
                hmac_result.deref(),
                passstruct.length,
                passstruct.cut,
                passstruct.no_symbols,
            )?)
            .unwrap();

            keyboard.key_down(enigo::Key::Control);
            keyboard.key_click(enigo::Key::Layout('v'));
            keyboard.key_up(enigo::Key::Control);

            std::thread::sleep(std::time::Duration::from_millis(100));

            ctx.set_contents(passstruct.username.to_owned()).unwrap();
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
        Opts::ExportKeyfile => std::fs::write(
            "yupass_keyfile",
            bincode::deserialize::<YuPassOpts>(
                std::fs::read(format!(
                    "{}/.yupassopts",
                    dirs::home_dir()
                        .context("Cannot find home directory")?
                        .display()
                ))?
                .as_slice(),
            )?
            .server_keyfile
            .context("Cannot find the server keyfile")?
            .to_bytes(),
        )?,
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
            let rev: u32 = match reqwest::blocking::Client::new()
                .post(format!("{}/request", server))
                .body(server_message!(b"rev", opts))
                .send()?
            {
                r if r.status() == StatusCode::FORBIDDEN => bail!("Invalid Signature"),
                r if r.status() == StatusCode::INTERNAL_SERVER_ERROR => bail!("Server error"),
                r => r,
            }
            .text()?
            .parse()?;
            if opts.rev != rev {
                let pgp = match reqwest::blocking::Client::new()
                    .post(format!("{}/request", server))
                    .body(server_message!(b"file", opts))
                    .send()?
                {
                    r if r.status() == StatusCode::FORBIDDEN => bail!("Invalid Signature"),
                    r if r.status() == StatusCode::INTERNAL_SERVER_ERROR => bail!("Server error"),
                    r => r,
                }
                .text()?
                .as_bytes()
                .to_vec();
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
    let keys: Vec<Key> = ctx
        .find_keys(vec![opts.key])?
        .filter_map(|x| x.ok())
        .collect();
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
    if let Some(server) = opts.server {
        let code = reqwest::blocking::Client::new()
            .post(format!("{}/upload", server))
            .body(bincode::serialize(&ServerMessage {
                message: output.clone(),
                signature: opts
                    .server_keyfile
                    .context("Server key file")?
                    .sign(output.as_slice()),
            })?)
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
