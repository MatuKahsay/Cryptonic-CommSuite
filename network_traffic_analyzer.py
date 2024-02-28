import os
import rsa
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
from cryptography.hazmat.primitives.ciphers import algorithms
import socket
import threading

# AES and Blowfish require a key and an initialization vector (IV)
# Fernet key generation is sufficient for AES, but Blowfish needs a different key size
def client_handler(client_socket, client_address, encryption_key, algorithm):
    while True:
        encrypted_msg = client_socket.recv(1024)
        if not encrypted_msg:
            break
        decrypted_msg = decrypt_message(algorithm, encryption_key, encrypted_msg)
        print(f"Message from {client_address}: {decrypted_msg}")