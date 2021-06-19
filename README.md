# YuPass

This is a Linux password manager powered by the YubiKey's HMAC-SHA1 challenge response slot. It encrypts a file using gpg which contains account notes, password options, and registered websites. Then it inputs the website title into the YubiKey and derives a password from the HMAC-SHA1 challenge response mode (Pro tip: Store the GPG private key on the YubiKey and the public key on your system for added security).

## Install

*   YuPass is available on the AUR

```bash
yay -S yupass
```

*   YuPass can also be built from source

```bash
cargo build --release
```

*   To initialize the password DB run this command (if you want to use a sync server, see [Cloud Syncing](#cloud-syncing)

```bash
target/release/yupass init <GPG KEY>
```

## TODO:

*   \[x] Cloud syncing
*   \[ ] Cross platform (Windows, MacOS, Linux, Android)
*   \[x] Notes

## Cloud Syncing

If you want to sync your passwords between Linux devices, like Bitwarden and others, follow these steps

1.  Get an instance running of YuSync by following the directions [here](StratusFearMe21)

2a.  If you have a password DB on your device already, simply move the file **.yupass.asc** in your home directory to YuSync's working directory and rename it **file**.

2b.  After completing 2a, run this command

```bash
yupass sync <GPG KEY> -s <SERVER URL>
```

3a.  If you dont have a password DB then run this command to initialize it on the server

```bash
yupass init <GPG KEY> -s <SERVER URL>
```

## Why YuPass?

1.  Recovery is very easy if you have a second YubiKey. If you set up both Yubikeys with the same HMAC secret, you won't lose any of your passwords if you lose one of your keys.

2.  If you lose your computer or the DB is deleted somehow, as long as you remember the settings for each of your passwords, just initializing a new database and adding the passwords back in is sufficient for recovering your passwords

3.  Passwords aren't stored anywhere, not even on your computer or [syncing server](https://github.com/StratusFearMe21/yusync). The passwords are always derived from your YubiKey, nowhere else.

4.  Passwords are very long for security. The default length for generated passwords in Bitwarden is 14 charecters, the YuPass default is 122 charecters. (The length of passwords is fully configurable).

# DISCLAIMER: I AM NOT A CYBERSECURITY EXPERT

It's not on me if you get hacked because you abused this application or you get hacked because I don't know how cybersecurity works.
