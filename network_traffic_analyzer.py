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


def start_chat_server(server_ip, server_port, encryption_key, algorithm):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(5)
    print(f"[*] Server listening on {server_ip}:{server_port}")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"[*] Accepted connection from {client_address[0]}:{client_address[1]}")
        client_thread = threading.Thread(target=client_handler, args=(client_socket, client_address, encryption_key, algorithm))
        client_thread.start()