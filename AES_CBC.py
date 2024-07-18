from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def AES_CBC_encrypt(plaintext, AES_key, initialization_vector):
    """
    Encrypts plaintext using AES in CBC mode with PKCS7 padding.

    :param plaintext: The plaintext to be encrypted.
    :param AES_key: The AES encryption key (16, 24, or 32 bytes).
    :param initialization_vector: The initialization vector (IV) for AES-CBC (16 bytes).
    :return: The ciphertext.
    """
    AES_CBC_cipher = AES.new(AES_key, AES.MODE_CBC, iv=initialization_vector)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = AES_CBC_cipher.encrypt(padded_plaintext)
    return ciphertext

def AES_CBC_decrypt(ciphertext, AES_key, initialization_vector):
    """
    Decrypts ciphertext encrypted with AES in CBC mode.

    :param ciphertext: The ciphertext to be decrypted.
    :param AES_key: The AES decryption key (16, 24, or 32 bytes).
    :param initialization_vector: The initialization vector (IV) used for encryption (16 bytes).
    :return: The decrypted plaintext.
    """
    AES_CBC_cipher = AES.new(AES_key, AES.MODE_CBC, iv=initialization_vector)
    decrypted_plaintext = AES_CBC_cipher.decrypt(ciphertext)
    unpadded_plaintext = unpad(decrypted_plaintext, AES.block_size)
    return unpadded_plaintext

# Input plaintext (ASCII encoding)
plaintext = input("Enter plaintext: ").encode("ASCII")

# Generate AES key and initialization vector (IV)
AES_key = get_random_bytes(16)
initialization_vector = get_random_bytes(16)

# Encrypt plaintext
ciphertext = AES_CBC_encrypt(plaintext, AES_key, initialization_vector)

# Decrypt ciphertext
decrypted_plaintext = AES_CBC_decrypt(ciphertext, AES_key, initialization_vector)

# Print results
print("Plaintext: ", plaintext.decode("ASCII"))
print("Ciphertext (hex): ", ciphertext.hex())
print("Decrypted plaintext: ", decrypted_plaintext.decode("ASCII"))
