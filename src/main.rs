use std::{collections::HashMap, ops::Deref, process::Command};

#[cfg(not(windows))]
use copypasta_ext::prelude::ClipboardProvider;

use enigo::KeyboardControllable;

use gpgme::{Context, Key, Protocol};

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

#[derive(Serialize, Deserialize, Debug, StructOpt)]
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

#[derive(Serialize, Deserialize, StructOpt, Debug)]
struct YuPassOpts {
    /// If using a syncing server, which one to use
    #[structopt(short)]
    server: Option<String>,
    key: String,
    #[structopt(skip)]
    rev: u32,
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
}

fn main() -> anyhow::Result<()> {
    let opts = Opts::from_args();
    match opts {
        Opts::Init { mut opts } => {
            opts.rev = 1;
            std::fs::write(
                format!("{}/.yupassopts", dirs::home_dir().unwrap().display()),
                bincode::serialize(&opts)?,
            )
            .unwrap();
            println!("{:?}", &opts);
            encrypt_passwords(HashMap::new(), opts)?;
        }
        Opts::Get => {
            let passwords = get_passwords()?;
            let mut yubi = Yubico::new();
            let device = yubi.find_yubikey().unwrap();
            let passopt = String::from_utf8(
                Command::new("zenity")
                    .arg("--list")
                    .arg("--column=Select Account")
                    .args(passwords.keys())
                    .output()
                    .unwrap()
                    .stdout,
            )
            .unwrap();
            println!("{}", passopt);
            let passstruct = passwords.get(passopt.trim()).unwrap();

            #[cfg(windows)]
            {
                unimplemented!("Windows support coming soon!");
            }

            #[cfg(not(windows))]
            {
                let mut keyboard = enigo::Enigo::new();

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
                    .unwrap();

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
        }
        Opts::Notes { title } => {
            println!(
                "{}",
                get_passwords()?
                    .get(&title)
                    .unwrap()
                    .notes
                    .clone()
                    .unwrap_or("No Notes".to_string())
            )
        }
        Opts::Add { title, password } => {
            println!("{:?}", password);
            let mut passwords = get_passwords()?;
            passwords.insert(title, password);
            encrypt_passwords(
                passwords,
                bincode::deserialize(
                    std::fs::read(format!(
                        "{}/.yupassopts",
                        dirs::home_dir().unwrap().display()
                    ))?
                    .as_slice(),
                )?,
            )?
        }
        Opts::Remove { title } => {
            let mut passwords = get_passwords()?;
            passwords.remove(&title).unwrap();
            encrypt_passwords(
                passwords,
                bincode::deserialize(
                    std::fs::read(format!(
                        "{}/.yupassopts",
                        dirs::home_dir().unwrap().display()
                    ))?
                    .as_slice(),
                )?,
            )?
        }
    }
    Ok(())
}

fn get_passwords() -> anyhow::Result<HashMap<String, PasswordOpts>> {
    let mut opts: YuPassOpts = bincode::deserialize(
        std::fs::read(format!(
            "{}/.yupassopts",
            dirs::home_dir().unwrap().display()
        ))?
        .as_slice(),
    )?;
    let mut input;
    match &opts.server {
        Some(server) => {
            let rev: u32 = reqwest::blocking::get(format!("{}/rev", server))?
                .text()?
                .parse()?;
            if opts.rev != rev {
                let pgp = reqwest::blocking::get(format!("{}/download", server))?
                    .text()?
                    .as_bytes()
                    .to_vec();
                std::fs::write(
                    format!("{}/.yupass.asc", dirs::home_dir().unwrap().display()),
                    &pgp,
                )?;
                opts.rev = rev;
                std::fs::write(
                    format!("{}/.yupassopts", dirs::home_dir().unwrap().display()),
                    bincode::serialize(&opts)?,
                )?;
                input = pgp;
            } else {
                input = std::fs::read_to_string(format!(
                    "{}/.yupass.asc",
                    dirs::home_dir().unwrap().display()
                ))?
                .as_bytes()
                .to_vec();
            }
        }
        None => {
            input = std::fs::read_to_string(format!(
                "{}/.yupass.asc",
                dirs::home_dir().unwrap().display()
            ))?
            .as_bytes()
            .to_vec()
        }
    }
    let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
    ctx.set_armor(true);
    let mut outbuf = Vec::new();
    ctx.decrypt(&mut input, &mut outbuf)?;
    Ok(bincode::deserialize(outbuf.as_slice()).unwrap())
}

fn encrypt_passwords(
    passwords: HashMap<String, PasswordOpts>,
    opts: YuPassOpts,
) -> anyhow::Result<()> {
    let mut output = Vec::new();
    let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
    ctx.set_armor(true);
    let keys: Vec<Key> = ctx
        .find_keys(vec![opts.key])?
        .filter_map(|x| x.ok())
        .collect();
    ctx.encrypt(&keys, bincode::serialize(&passwords)?, &mut output)?;
    std::fs::write(
        format!("{}/.yupass.asc", dirs::home_dir().unwrap().display()),
        &output,
    )?;
    if let Some(server) = opts.server {
        reqwest::blocking::Client::new()
            .post(format!("{}/upload", server))
            .body(output)
            .send()?;
    }
    Ok(())
}

// Code stolen from base91 crate
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
