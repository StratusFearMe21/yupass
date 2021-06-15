use std::{
    collections::HashMap,
    fs::File,
    io::Write,
    process::{Command, Stdio},
};

use dmenu_facade::DMenu;
use enigo::KeyboardControllable;
use gpgme::{Context, Error, Key, Protocol};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

#[derive(Serialize, Deserialize, Debug, StructOpt)]
struct PasswordOpts {
    /// Usesrname of the account in question
    username: String,
    /// Whether or not to remove symbols from passwords
    #[structopt(short)]
    nosymbols: bool,
    /// Cuts password to certain length
    #[structopt(short)]
    length: Option<u8>,
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
    /// Add a password
    Add {
        /// Username of the account in question
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

fn main() -> Result<(), Error> {
    let opts = Opts::from_args();
    match opts {
        Opts::Init { key } => {
            std::fs::write("/home/isaacm/.yupasskey", &key).unwrap();
            encrypt_passwords(HashMap::new(), key)?;
            println!("Passwords initialized");
        }
        Opts::Get => {
            let passwords = get_passwords()?;
            let passkeys: Vec<String> = passwords.keys().cloned().collect();
            let passopt = DMenu::default().execute(&passkeys).unwrap();
            enigo::Enigo::new().key_sequence(
                &String::from_utf8(
                    Command::new("ykchalresp")
                        .arg("-2")
                        .arg(passopt)
                        .output()
                        .unwrap()
                        .stdout,
                )
                .unwrap(),
            );

            Command::new("xsel")
                .arg("-b")
                .stdin(Stdio::piped())
                .spawn()
                .unwrap()
                .stdin
                .unwrap()
                .write_all(passwords.get(passopt).unwrap().username.as_bytes())
                .unwrap();
        }
        Opts::Add { title, password } => {
            let mut passwords = get_passwords()?;
            passwords.insert(title, password);
            encrypt_passwords(
                passwords,
                std::fs::read_to_string("/home/isaacm/.yupasskey").unwrap(),
            )?;
        }
        Opts::Remove { title } => {
            let mut passwords = get_passwords()?;
            passwords.remove(&title).unwrap();
            encrypt_passwords(
                passwords,
                std::fs::read_to_string("/home/isaacm/.yupasskey").unwrap(),
            )?;
        }
    }
    Ok(())
}

fn get_passwords() -> Result<HashMap<String, PasswordOpts>, Error> {
    let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
    ctx.set_armor(true);
    let mut input = File::open("/home/isaacm/.yupass.asc")
        .map_err(|e| format!("can't open file `/home/isaacm/.yupass.asc': {:?}", e))
        .unwrap();
    let mut outbuf = Vec::new();
    ctx.decrypt(&mut input, &mut outbuf)
        .map_err(|e| format!("decrypting failed: {:?}", e))
        .unwrap();
    Ok(bincode::deserialize(outbuf.as_slice()).unwrap())
}

fn encrypt_passwords(passwords: HashMap<String, PasswordOpts>, key: String) -> Result<(), Error> {
    let mut file = File::create("/home/isaacm/.yupass.asc").unwrap();
    let mut ctx = Context::from_protocol(Protocol::OpenPgp)?;
    ctx.set_armor(true);
    let keys: Vec<Key> = ctx.find_keys(vec![key])?.filter_map(|x| x.ok()).collect();
    ctx.encrypt(&keys, bincode::serialize(&passwords).unwrap(), &mut file)
        .map_err(|e| format!("encrypting failed: {:?}", e))
        .unwrap();
    Ok(())
}
