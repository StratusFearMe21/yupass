# YuPass

This is a Linux password manager powered by the YubiKey's HMAC-SHA1 challenge response slot. It encrypts a file using gpg which contains account notes, password options, and registered websites. Then it inputs the website title into the YubiKey and derives a password from the HMAC-SHA1 challenge response mode (Pro tip: Store the GPG private key on the YubiKey and the public key on your system for added security).

# TODO:

*   \[x] Cloud syncing
*   \[ ] Cross platform (Windows, MacOS, Linux, Android)
*   \[x] Notes

# Cloud Syncing

If you want to sync your passwords between Linux devices, like Bitwarden and others, follow these steps

1.  Get an instance running of YuSync by following the directions [here](https://github.com/StratusFearMe21/yusync)

2a.  If you have a password DB on your device already, simply move the file **.yupass.asc** in your home directory to YuSync's working directory and rename it **file**.

2b.  After completing 2a, run this command

```bash
yupass sync <GPG KEY> -s <SERVER URL>
```

3a.  If you dont have a password DB then run this command to initialize it on the server

```bash
yupass init <GPG KEY> -s <SERVER URL>
```

# DISCLAIMER: I AM NOT A CYBERSECURITY EXPERT

It's not on me if you get hacked because you abused this application or you get hacked because I don't know how cybersecurity works.
