import socket
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

PORT = 5000

# Load receiver private key
with open("private_key.pem", "rb") as f:
    receiver_private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

server = socket.socket()
server.bind(("", PORT))
server.listen(1)

print("Waiting for secure file...")
conn, addr = server.accept()

# Receive encrypted AES key
key_len = int.from_bytes(conn.recv(4), "big")
encrypted_aes_key = conn.recv(key_len)

aes_key = receiver_private_key.decrypt(
    encrypted_aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Receive IV
iv = conn.recv(16)

# Receive sender public key
pub_len = int.from_bytes(conn.recv(4), "big")
sender_public_bytes = conn.recv(pub_len)
sender_public_key = serialization.load_pem_public_key(sender_public_bytes)

# Receive signature
sig_len = int.from_bytes(conn.recv(4), "big")
signature = conn.recv(sig_len)

# Receive encrypted file
data_len = int.from_bytes(conn.recv(8), "big")
ciphertext = conn.recv(data_len)

# Receive hash
received_hash = conn.recv(32)

# Decrypt file
cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

# Verify hash
digest = hashes.Hash(hashes.SHA256())
digest.update(plaintext)
calculated_hash = digest.finalize()

# Verify signature
sender_public_key.verify(
    signature,
    received_hash,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

if calculated_hash == received_hash:
    with open("received_file.txt", "wb") as f:
        f.write(plaintext)
    print("File received, verified, and decrypted successfully.")
else:
    print("Integrity check failed.")

conn.close()
server.close()
