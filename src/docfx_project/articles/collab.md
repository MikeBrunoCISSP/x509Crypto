# Seeking Collaborators!

I'd like to implement some enhancements for the X509Crypto library and would welcome some collaborators to help out. 

## Implement support for eliptic curve cryptography (ECC)

Currently, the library only supports RSA-based keys and encryption.  With the advent of quantum computing, RSA's days are numbered.  In order to ensure the continued utility of this library, I definitely need to provide support for ECC (while maintaining legacy support for RSA).  I am admittedly not a cryptographer and would welcome the input/help of someone who knows more than me.

## Test/Implement support for leveraging certificates with HSM-protected keys

Utilizing Hardware Security Modules (HSMs) to store encryption keys provides a much better security posture than storing them directly in MS CAPI. I could use assistance in terms of testing the X509Crypto library with HSMs manufactured by both Thales and Gemalto-SafeNet. I am doubtful that the library will work as-is, so there is probably a development opportunity here as well.

## Security-focused Code Review

I would appreciate having the core encryption and decryption methods in the X509Crypto library reviewed by a resource who is experienced with crypto development. A second pair of eyes is always a good thing! 

<a href="mailto:mikebrunocissp@gmail.com">Contact me</a> if you're interested in working together!