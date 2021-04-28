from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding

def encrypt_file(file, public_key):

    encrypted = public_key.encrypt(
        file,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def aes_encrypt(iv, aes_key, unencrypted_file):

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padder = aes_padding.PKCS7(128).padder()
    padded_data = padder.update(unencrypted_file) + padder.finalize()
    ct = encryptor.update(padded_data) + encryptor.finalize() # encrypted data
    return ct

def aes_decrypt(aes_key, iv, ct):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decoded = decryptor.update(ct) + decryptor.finalize()
    unpadder = aes_padding.PKCS7(128).unpadder()
    decoded_unpadded_file = unpadder.update(decoded) + unpadder.finalize()
    return decoded_unpadded_file

def rsa_decrypt(encrypted_item, private_key):
    decrypted = private_key.decrypt(
        encrypted_item,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

def get_private_key():
    with open("./keys/rsa_private_key.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
                return private_key

def get_public_key():
    public_key = serialization.load_pem_public_key(
        open("./keys/rsa_public_key.pem", "rb").read(),
        backend=default_backend()
    )
    return public_key