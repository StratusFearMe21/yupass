use std::{collections::HashMap, fs::File, ops::Deref, process::Command};

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
}

#[derive(StructOpt)]
#[structopt(name = "YuPass", about = "A password manager, powered by the YubiKey")]
enum Opts {
    /// Initialize the password database
    Init {
        /// GPG key to encrypt passwords with
        key: String,
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
        Opts::Init { key } => {
            std::fs::write(
                format!("{}/.yupasskey", dirs::home_dir().unwrap().display()),
                &key,
            )
            .unwrap();
            encrypt_passwords(HashMap::new(), key)?;
            println!("Passwords initialized");
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
            let passstruct = passwords.get(passopt.trim()).unwrap();
            #[cfg(not(windows))]
            {
                let mut ctx = copypasta_ext::x11_fork::ClipboardContext::new().unwrap();
                ctx.set_contents(passstruct.username.to_owned()).unwrap();
            }

            #[cfg(windows)]
            {
                clipboard_win::set_clipboard(clipboard_win::formats::Unicode, &passstruct.username)
                    .unwrap();
            }

            let mut keyboard = enigo::Enigo::new();
            let mut key: u32;
            let mut rem: u32 = 0;
            let mut shift: u32 = 0;
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

            for _ in 0..passstruct.length {
                for c in hmac_result.deref() {
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

                        keyboard.key_click(enigo::Key::Layout(ENTAB[(key % 91) as usize]));
                        keyboard.key_click(enigo::Key::Layout(ENTAB[(key / 91) as usize]));
                    }
                }
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
                std::fs::read_to_string(format!(
                    "{}/.yupasskey",
                    dirs::home_dir().unwrap().display()
                ))
                .unwrap(),
            )?;
        }
        Opts::Remove { title } => {
            let mut passwords = get_passwords()?;
            passwords.remove(&title).unwrap();
            encrypt_passwords(
                passwords,
                std::fs::read_to_string(format!(
                    "{}/.yupasskey",
                    dirs::home_dir().unwrap().display()
                ))
                .unwrap(),
            )?;
        }
    }
    Ok(())
}

fn get_passwords() -> anyhow::Result<HashMap<String, PasswordOpts>> {
    let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
    ctx.set_armor(true);
    let mut input = File::open(format!(
        "{}/.yupass.asc",
        dirs::home_dir().unwrap().display()
    ))?;
    let mut outbuf = Vec::new();
    ctx.decrypt(&mut input, &mut outbuf)?;
    Ok(bincode::deserialize(outbuf.as_slice()).unwrap())
}

fn encrypt_passwords(passwords: HashMap<String, PasswordOpts>, key: String) -> anyhow::Result<()> {
    let mut file = File::create(format!(
        "{}/.yupass.asc",
        dirs::home_dir().unwrap().display()
    ))?;
    let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
    ctx.set_armor(true);
    let keys: Vec<Key> = ctx.find_keys(vec![key])?.filter_map(|x| x.ok()).collect();
    let serialize = bincode::serialize(&passwords)?;
    ctx.encrypt(&keys, serialize, &mut file)?;
    Ok(())
}
