from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def AES_GCM_encrypt(plaintext, AES_key, nonce):
    """
    Encrypts plaintext using AES in GCM mode.

    :param plaintext: The plaintext to be encrypted.
    :param AES_key: The AES encryption key (16, 24, or 32 bytes).
    :param nonce: The nonce (number used once) for AES-GCM (12 bytes).
    :return: The ciphertext and the authentication tag.
    """
    AES_GCM_cipher = AES.new(AES_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = AES_GCM_cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag

def AES_GCM_decrypt(ciphertext, AES_key, nonce, tag):
    """
    Decrypts ciphertext encrypted with AES in GCM mode.

    :param ciphertext: The ciphertext to be decrypted.
    :param AES_key: The AES decryption key (16, 24, or 32 bytes).
    :param nonce: The nonce used for encryption (12 bytes).
    :param tag: The authentication tag generated during encryption.
    :return: The decrypted plaintext if authentication succeeds, or raises ValueError if authentication fails.
    """
    AES_GCM_cipher = AES.new(AES_key, AES.MODE_GCM, nonce=nonce)
    decrypted_plaintext = AES_GCM_cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_plaintext

# Input plaintext (ASCII encoding)
plaintext = input("Enter plaintext: ").encode("ASCII")

# Generate AES key and nonce
AES_key = get_random_bytes(16)
nonce = get_random_bytes(12)

# Encrypt plaintext
ciphertext, tag = AES_GCM_encrypt(plaintext, AES_key, nonce)

# Decrypt ciphertext
decrypted_plaintext = AES_GCM_decrypt(ciphertext, AES_key, nonce, tag)

# Print results
print("Plaintext: ", plaintext.decode("ASCII"))
print("Ciphertext (hex): ", ciphertext.hex())
print("Decrypted plaintext: ", decrypted_plaintext.decode("ASCII"))
