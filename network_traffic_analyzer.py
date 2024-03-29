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
    
def chat_client(server_ip, server_port, encryption_key, algorithm):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, server_port))

    while True:
        message = input("Enter message: ")
        if message == "quit":
            break
        encrypted_msg = encrypt_message(algorithm, encryption_key, message)
        client_socket.send(encrypted_msg)

        if algorithm == 'AES':
            key = os.urandom(32)  # 256-bit key
            iv = os.urandom(16)   # AES block size is 128 bits (16 bytes)
            with open(f'{algorithm}_key.pem', 'wb') as key_file:
                key_file.write(key)
            with open(f'{algorithm}_iv.pem', 'wb') as iv_file:
                iv_file.write(iv)
            return key, iv
        
        elif algorithm == 'Blowfish':
            key = os.urandom(32)  # Blowfish key can vary; using 256 bits here for simplicity
            iv = os.urandom(8)    # Blowfish block size is 64 bits (8 bytes)
            with open(f'{algorithm}_key.pem', 'wb') as key_file:
                key_file.write(key)
            with open(f'{algorithm}_iv.pem', 'wb') as iv_file:
                iv_file.write(iv)
            return key, iv
        
        elif algorithm == 'RSA':
            private_key = crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()

            # Save the private key
            with open(f'{algorithm}_private.pem', 'wb') as priv_key_file:
                priv_key_file.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                )

            # Save the public key
            with open(f'{algorithm}_public.pem', 'wb') as pub_key_file:
                pub_key_file.write(
                    public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                )

            return public_key, private_key

        else:
            raise ValueError("Unsupported algorithm")
   
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
    
def save_key_to_file(key, algorithm, is_private=True):
    suffix = "private" if is_private else "public"
    file_name = f"{algorithm}_{suffix}.pem"
    if algorithm in ['AES', 'Blowfish', 'Fernet']:
        with open(file_name, 'wb') as key_file:
            key_file.write(key)
    elif algorithm == 'RSA':
        with open(file_name, 'wb') as key_file:
            key_data = key.save_pkcs1()
            key_file.write(key_data)
    print(f"Key saved to {file_name}")

def load_key_from_file(file_path, algorithm, is_private=True):
    with open(file_path, 'rb') as key_file:
        key_data = key_file.read()
    if algorithm in ['AES', 'Blowfish', 'Fernet']:
        return key_data
    elif algorithm == 'RSA':
        if is_private:
            return rsa.PrivateKey.load_pkcs1(key_data)
        else:
            return rsa.PublicKey.load_pkcs1(key_data)
        
if __name__ == "__main__":
    algorithm = input("Enter the encryption algorithm (Fernet, AES, Blowfish, RSA): ")
    
    if algorithm not in ['Fernet', 'AES', 'Blowfish', 'RSA']:
        print("Invalid algorithm selected.")
    else:
        key = generate_key(algorithm)
        operation = input("Choose operation: encrypt or decrypt: ")
        if operation == "encrypt":
            input_file_path = input("Enter the input file path: ")
            output_file_path = input("Enter the output file path: ")
            encrypt_file(algorithm, key, input_file_path, output_file_path)
            print(f"File encrypted successfully. Encrypted file is at {output_file_path}")
        elif operation == "decrypt":
            input_file_path = input("Enter the encrypted file path: ")
            output_file_path = input("Enter the output file path: ")
            decrypt_file(algorithm, key, input_file_path, output_file_path)
            print(f"File decrypted successfully. Decrypted file is at {output_file_path}")
        else:
            print("Invalid operation selected.")