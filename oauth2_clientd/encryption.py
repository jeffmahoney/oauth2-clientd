#!/usr/bin/python3

import getpass
import os
import sys

from typing import Dict, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .helpers import b64decode, b64encode_str

class NoPrivateKeyError(RuntimeError):
    """Cannot unlock private key"""

def generate_rsa_private_key() -> rsa.RSAPrivateKeyWithSerialization:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048,
                                    backend=default_backend())

def encrypt_private_key(private_key: rsa.RSAPrivateKeyWithSerialization,
                        password_bytes: bytes) -> bytes:

    encryption = serialization.BestAvailableEncryption(password_bytes)
    return private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                     format=serialization.PrivateFormat.PKCS8,
                                     encryption_algorithm=encryption)

def get_password(minlen: int = 10) -> bytes:
    password_bytes = None
    while password_bytes is None:
        try:
            pw1 = getpass.getpass(f"Enter password for new private key (min {minlen} chars): ")
            if len(pw1) < 10:
                print(f"Password too short.  Must be longer than {minlen} characters.",
                      file=sys.stderr)
                continue
            pw2 = getpass.getpass("Repeat: ")
        except (KeyboardInterrupt, EOFError) as ex:
            raise NoPrivateKeyError("Cannot create private key without password.") from ex

        if pw1 == pw2:
            password_bytes = bytes(pw1.encode())
        else:
            print("Passwords don't match.  Try again.")

    return password_bytes

def serialize_public_key(public_key: rsa.RSAPublicKeyWithSerialization) -> bytes:
    return public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)

def generate_rsa_keypair() -> Dict[str, bytes]:
    private_key = generate_rsa_private_key()
    password = get_password()
    private_key_pem = encrypt_private_key(private_key, password)
    public_key_pem = serialize_public_key(private_key.public_key())

    keypair = {
        'public_key_pem' : public_key_pem,
        'private_key_pem' : private_key_pem,
        }

    del private_key

    return keypair

def crypto_padding() -> padding.OAEP:
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(), label=None)

def encrypt(public_key_pem: bytes, data: bytes) -> Tuple[bytes, Dict[str, str]]:
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Expected RSA key, got {type(public_key)}")

    key = os.urandom(32)
    nonce = os.urandom(16)

    params: Dict[str, str] = {
        'algo' : 'AES',
        'mode' : 'CTR',
        'key' : b64encode_str(public_key.encrypt(key, crypto_padding())),
        'nonce' : b64encode_str(nonce),
    }

    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    return encrypted_data, params


def decrypt(private_key: rsa.RSAPrivateKeyWithSerialization, cryptoparams: Dict[str, str],
            data: bytes) -> bytes:

    if cryptoparams['algo'] != 'AES':
        raise NotImplementedError(f"Support for cryptographic algorithm {cryptoparams['algo']} not implemented.")

    if cryptoparams['mode'] != 'CTR':
        raise NotImplementedError(f"Support for cryptographic mode {cryptoparams['mode']} not implemented.")

    key = private_key.decrypt(b64decode(cryptoparams['key']), crypto_padding())
    del private_key

    nonce = b64decode(cryptoparams['nonce'])
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

def decrypt_private_key(private_key_pem: bytes,
                        password_bytes: bytes) -> rsa.RSAPrivateKey:
    ret = serialization.load_pem_private_key(private_key_pem, password=password_bytes,
                                             backend=default_backend())
    if not isinstance(ret, rsa.RSAPrivateKey):
        raise TypeError(f"Expected RSAPrivateKey not {type(ret)}")

    return ret
