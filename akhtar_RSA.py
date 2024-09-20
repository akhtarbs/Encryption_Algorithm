# RSA (Rivest–Shamir–Adleman) with cryptography

# RSA is an asymmetric encryption algorithm, 
# meaning it uses a public key for encryption 
# and a private key for decryption.

# Run this code in your terminal
# code: pip install cryptography

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Generate RSA keys
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Public key encryption
plaintext = "This is a secret message"
plaintext = bytes(plaintext, 'utf-8')

ciphertext = public_key.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
# print("Encrypted (RSA):", ciphertext)
print("Encrypted (RSA) in Hexa:", ciphertext.hex())

# Private key decryption
decrypted_message = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Decrypted (RSA):", decrypted_message.decode())
