# YuPass

This is a Linux password manager powered by the YubiKey's HMAC-SHA1 challenge response slot. It encrypts a file using gpg which contains account notes, password options, and registered websites. Then it inputs the website title into the YubiKey and derives a password from the HMAC-SHA1 challenge response mode (Pro tip: Store the GPG private key on the YubiKey and the public key on your system for added security).

## An interesting novelty, but this is not practical
I've been using this password manager for about a year now and I've come to realize
that this password manager is not practical at all. All the steps of running the
`get` command, typing in the website, etc. gets really old, really fast. Especially
when you need to type in your password on other platforms other than Linux. This
password manager exists because I wanted my passwords to be more secure, but honestly,
Bitwarden is just as secure, but also easier to use than my password manager. If you too
have been using this password manager, I urge you to switch to a better solution such
as Bitwarden. This program now has an export function that will make an `export.json`
file which you can import into Bitwarden.
