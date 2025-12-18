import socket
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

RECEIVER_IP = "RECIVER_IP"
PORT = 5000
FILE_NAME = "sample.txt"

# Load receiver public key
with open("public_key.pem", "rb") as f:
    receiver_public_key = serialization.load_pem_public_key(f.read())

# Generate AES session key
aes_key = os.urandom(32)
iv = os.urandom(16)

# Encrypt AES key using RSA
encrypted_aes_key = receiver_public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Read file
with open(FILE_NAME, "rb") as f:
    plaintext = f.read()

# Encrypt file using AES
cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

# Generate SHA-256 hash
digest = hashes.Hash(hashes.SHA256())
digest.update(plaintext)
file_hash = digest.finalize()

# Generate temporary sender RSA key (for signature)
sender_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
sender_public_key = sender_private_key.public_key()

# Sign hash
signature = sender_private_key.sign(
    file_hash,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Serialize sender public key
sender_public_bytes = sender_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Send data
client = socket.socket()
client.connect((RECEIVER_IP, PORT))

client.send(len(encrypted_aes_key).to_bytes(4, "big"))
client.send(encrypted_aes_key)

client.send(iv)

client.send(len(sender_public_bytes).to_bytes(4, "big"))
client.send(sender_public_bytes)

client.send(len(signature).to_bytes(4, "big"))
client.send(signature)

client.send(len(ciphertext).to_bytes(8, "big"))
client.send(ciphertext)

client.send(file_hash)

client.close()
print("Secure file sent successfully.")
