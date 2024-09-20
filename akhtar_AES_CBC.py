# AES (Advanced Encryption Standard) (CBC Mode) with PyCryptodome

# AES is a symmetric key encryption algorithm, 
# where the same key is used for encryption and decryption.


# Run this code in your terminal
# code: pip install pycryptodome

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Function to add padding to the plaintext to match AES block size (16 bytes)
def pad(plaintext):
    block_size = AES.block_size
    pad_len = block_size - len(plaintext) % block_size
    return plaintext + (chr(pad_len) * pad_len).encode()

# Function to remove padding from decrypted text
def unpad(plaintext):
    pad_len = plaintext[-1]
    return plaintext[:-pad_len]

# Encryption function using AES CBC mode
def encrypt(plaintext, key):
    # Generate a random IV (Initialization Vector)
    iv = get_random_bytes(AES.block_size)
    
    # Create AES cipher object in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad the plaintext and then encrypt it
    padded_plaintext = pad(plaintext.encode())
    ciphertext = cipher.encrypt(padded_plaintext)
    
    # Return the IV and ciphertext encoded as base64 for easier handling
    return base64.b64encode(iv + ciphertext).decode()

# Decryption function using AES CBC mode
def decrypt(ciphertext_base64, key):
    # Decode the base64-encoded input
    ciphertext_bytes = base64.b64decode(ciphertext_base64)
    
    # Extract the IV from the ciphertext (first block_size bytes)
    iv = ciphertext_bytes[:AES.block_size]
    ciphertext = ciphertext_bytes[AES.block_size:]
    
    # Create AES cipher object in CBC mode for decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt and unpad the decrypted plaintext
    decrypted_padded_plaintext = cipher.decrypt(ciphertext)
    return unpad(decrypted_padded_plaintext).decode()

# Example usage
if __name__ == "__main__":
    # 256-bit (32-byte) AES key (must be either 16, 24, or 32 bytes long)
    key = get_random_bytes(32)
    
    plaintext = "This is a secret message"
    
    print(f"Original plaintext: {plaintext}")
    
    # Encrypt the plaintext
    encrypted = encrypt(plaintext, key)
    print(f"Encrypted (base64): {encrypted}")
    
    # Decrypt the ciphertext
    decrypted = decrypt(encrypted, key)
    print(f"Decrypted plaintext: {decrypted}")
