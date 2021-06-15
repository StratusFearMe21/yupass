# YuPass

This is a Linux password manager powered by the YubiKey's HMAC-SHA1 challenge response slot. It encrypts a file using gpg which contains account notes, password options, and registered websites. Then it inputs the website title into the YubiKey and derives a password from the HMAC-SHA1 challenge response mode (Pro tip: Store the GPG private key on the YubiKey and the public key on your system for added security).

# TODO:

*   \[ ] Cloud syncing
*   \[ ] Cross platform (Windows, MacOS, Linux, Android)
*   \[x] Notes

# DISCLAIMER: I AM NOT A CYBERSECURITY EXPERT

It's not on me if you get hacked because you abused this application or you get hacked because I don't know how cybersecurity works.
