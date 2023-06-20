# Cryptography
Implementation of KMACXOF256 and Schnorr/DHIES

Uses the cryptographically secure function KMACXOF256 to:
- Compute a plain cryptographic hash of given text (text file or command line input).
- Compute an authentication tag (MAC) of given text (text file or command line input) under a given passphrase.
- Encrypt a given data file symmetrically under a given passphrase.
- Decrypt a given symmetric cryptogram under a given passphrase.

Uses DHIES encryption and Schnorr signatures with elliptic curves to:
- Generate an elliptic key pair from a given passphrase and write the public key to a file.
- Encrypt given text (text file or command line input) under a given elliptic public key file and write the ciphertext to a file.
- Decrypt a given elliptic-encrypted file from a given password and write the decrypted data to a file.
- Sign given text (text file or command line input) from a given password and write the signature to a file.
- Verify a given data file and its signature file under a given public key file.
