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

def generate_key(algorithm):
    if algorithm == 'Fernet':
        key = Fernet.generate_key()
        with open(f'{algorithm}_key.pem', 'wb') as key_file:
            key_file.write(key)
        return key
    
def encrypt_file(algorithm, key, input_file_path, output_file_path):
    with open(input_file_path, 'rb') as file_to_encrypt:
        message = file_to_encrypt.read()
        encrypted_message = encrypt_message(algorithm, key, message)
        with open(output_file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_message)

def decrypt_file(algorithm, key, input_file_path, output_file_path):
    with open(input_file_path, 'rb') as file_to_decrypt:
        encrypted_message = file_to_decrypt.read()
        decrypted_message = decrypt_message(algorithm, key, encrypted_message)
        with open(output_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_message)

def encrypt_message(algorithm, key, message):
    if algorithm == 'Fernet':
        cipher_suite = Fernet(key)
        encrypted_message = cipher_suite.encrypt(message.encode())
        return encrypted_message
    elif algorithm == 'AES':
        cipher = Cipher(algorithms.AES(key[0]), modes.CFB(key[1]), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(message.encode()) + encryptor.finalize()
    elif algorithm == 'Blowfish':
        cipher = Cipher(algorithms.Blowfish(key[0]), modes.CFB(key[1]), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(message.encode()) + encryptor.finalize()
    elif algorithm == 'RSA':
        encrypted_message = rsa.encrypt(message.encode(), key)
        return encrypted_message
    
def decrypt_message(algorithm, key, encrypted_message):
    if algorithm == 'Fernet':
        cipher_suite = Fernet(key)
        return cipher_suite.decrypt(encrypted_message).decode()
    elif algorithm == 'AES':
        cipher = Cipher(algorithms.AES(key[0]), modes.CFB(key[1]), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_message) + decryptor.finalize()
    elif algorithm == 'Blowfish':
        cipher = Cipher(algorithms.Blowfish(key[0]), modes.CFB(key[1]), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted_message) + decryptor.finalize()
    elif algorithm == 'RSA':
        # For RSA, the key should be the private key
        decrypted_message = rsa.decrypt(encrypted_message, key).decode()
        return decrypted_message