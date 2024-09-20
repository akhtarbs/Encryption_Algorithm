#  Blowfish (CBC Mode) with PyCryptodome 

# Blowfish is another symmetric key 
# encryption algorithm known for its speed.


# Run this code in your terminal
# code: pip install pycryptodome

from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
import base64

# Function to add padding to the plaintext to match Blowfish block size (8 bytes)
def pad(plaintext):
    block_size = Blowfish.block_size
    pad_len = block_size - len(plaintext) % block_size
    return plaintext + (chr(pad_len) * pad_len).encode()

# Function to remove padding from decrypted text
def unpad(plaintext):
    pad_len = plaintext[-1]
    return plaintext[:-pad_len]

# Encryption function using Blowfish CBC mode
def encrypt(plaintext, key):
    # Generate a random IV (Initialization Vector)
    iv = get_random_bytes(Blowfish.block_size)
    
    # Create Blowfish cipher object in CBC mode
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    
    # Pad the plaintext and then encrypt it
    padded_plaintext = pad(plaintext.encode())
    ciphertext = cipher.encrypt(padded_plaintext)
    
    # Return the IV and ciphertext encoded as base64 for easier handling
    return base64.b64encode(iv + ciphertext).decode()

# Decryption function using Blowfish CBC mode
def decrypt(ciphertext_base64, key):
    # Decode the base64-encoded input
    ciphertext_bytes = base64.b64decode(ciphertext_base64)
    
    # Extract the IV from the ciphertext (first block_size bytes)
    iv = ciphertext_bytes[:Blowfish.block_size]
    ciphertext = ciphertext_bytes[Blowfish.block_size:]
    
    # Create Blowfish cipher object in CBC mode for decryption
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    
    # Decrypt and unpad the decrypted plaintext
    decrypted_padded_plaintext = cipher.decrypt(ciphertext)
    return unpad(decrypted_padded_plaintext).decode()

# Example usage
if __name__ == "__main__":
    # Blowfish key (must be between 4 and 56 bytes long)
    key = get_random_bytes(16)  # 16 bytes key length is used here
    
    plaintext = "This is a secret message"
    
    print(f"Original plaintext: {plaintext}")
    
    # Encrypt the plaintext
    encrypted = encrypt(plaintext, key)
    print(f"Encrypted (base64): {encrypted}")
    
    # Decrypt the ciphertext
    decrypted = decrypt(encrypted, key)
    print(f"Decrypted plaintext: {decrypted}")
