import socket
import smtplib, ssl
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')

smtp_server = "smtp.gmail.com"
port = 587
sender_email = "gavinjsenger@gmail.com"
password = "Nyu12345!"

context = ssl.create_default_context()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((socket.gethostname(), 1234))

peer_aes_parameters = s.recv(2048)

pn = dh.DHParameterNumbers(int_from_bytes(peer_aes_parameters), 2)
parameters = pn.parameters()

aes_private_key = parameters.generate_private_key()
aes_public_key = aes_private_key.public_key()
aes_public_numbers = aes_public_key.public_numbers()

peer_aes_public_y = s.recv(2048)
s.send(int_to_bytes(aes_public_numbers.y))

peer_aes_public_numbers = dh.DHPublicNumbers(int_from_bytes(peer_aes_public_y), pn)
peer_aes_public_key = peer_aes_public_numbers.public_key()

aes_shared_key = aes_private_key.exchange(peer_aes_public_key)
derived_aes_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'test',).derive(aes_shared_key)

nonce_private_key = parameters.generate_private_key()
nonce_public_key = nonce_private_key.public_key()
nonce_public_numbers = nonce_public_key.public_numbers()

peer_nonce_public_y = s.recv(2048)
s.send(int_to_bytes(nonce_public_numbers.y))

peer_nonce_public_numbers = dh.DHPublicNumbers(int_from_bytes(peer_nonce_public_y), pn)
peer_nonce_public_key = peer_nonce_public_numbers.public_key()

nonce_shared_key = nonce_private_key.exchange(peer_nonce_public_key)
derived_nonce_key = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b'test',).derive(nonce_shared_key)

cipher = Cipher(algorithms.AES(derived_aes_key), modes.CTR(derived_nonce_key))
encryptor = cipher.encryptor()
ct = encryptor.update(b'Hello! Welcome to our demonstration. If you see this message, it worked!') + encryptor.finalize()
message = str(ct)

try:
    server = smtplib.SMTP(smtp_server, port)
    server.ehlo()
    server.starttls(context=context)
    server.ehlo()
    server.login(sender_email, password)
    server.sendmail(sender_email, "accttesting679@gmail.com", message)
    s.send(b"Run")
except Exception as e: print(e)
finally: server.quit()
