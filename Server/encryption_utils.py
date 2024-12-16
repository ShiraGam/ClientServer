from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
from config import constants

def encrypt_aes_key(public_key_bytes:bytes, aes_key:bytes) ->bytes:
    """
    Encrypts the given AES key using the provided RSA public key.
    """
    # Load the public key
    public_key = RSA.import_key(public_key_bytes)

    cipher = PKCS1_OAEP.new(public_key)

    # Encrypt the AES key
    encrypted_aes_key = cipher.encrypt(aes_key)

    return encrypted_aes_key

# AES decryption function
def decrypt_file(encrypted_file, aes_key, iv):
    """
    Decrypt the given encrypted file using AES (CBC mode) and return the decrypted data.
    :param encrypted_file: The encrypted file data (in bytes).
    :param aes_key: The AES key (in bytes) used for decryption.
    :param iv: The initialization vector (IV) used for AES decryption.
    :return: Decrypted file data (in bytes).
    """
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_file), AES.block_size)
    return decrypted_data


