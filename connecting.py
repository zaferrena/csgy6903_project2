import socket
import imaplib, email, time
from ast import literal_eval
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')

def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')

imap_url = "imap.gmail.com"
user = "accttesting679@gmail.com"
password = "Account testing her3"
M = imaplib.IMAP4_SSL(imap_url)

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
print(derived_aes_key)

nonce_private_key = parameters.generate_private_key()
nonce_public_key = nonce_private_key.public_key()
nonce_public_numbers = nonce_public_key.public_numbers()

peer_nonce_public_y = s.recv(2048)
s.send(int_to_bytes(nonce_public_numbers.y))

peer_nonce_public_numbers = dh.DHPublicNumbers(int_from_bytes(peer_nonce_public_y), pn)
peer_nonce_public_key = peer_nonce_public_numbers.public_key()

nonce_shared_key = nonce_private_key.exchange(peer_nonce_public_key)
derived_nonce_key = HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=b'test',).derive(nonce_shared_key)
print(derived_nonce_key)

s.recv(2048)
time.sleep(20)

M.login(user, password)
M.select('Inbox')
result, data = M.uid('search', None, "ALL")
if result == 'OK':
    num = data[0].split()[-1]
    result, data = M.uid('fetch', num, '(RFC822)')
    if result == 'OK':
        email_message = email.message_from_bytes(data[0][1])
        message = str(email_message.get_payload())
        decodedString = literal_eval("{}".format(message))
        print(decodedString, type(decodedString))
        cipher = Cipher(algorithms.AES(derived_aes_key), modes.CTR(derived_nonce_key))
        decryptor = cipher.decryptor()
        pt = decryptor.update(decodedString) + decryptor.finalize()
        print('Date:' + email_message['Date'])
        print(pt.decode('utf-8'))
