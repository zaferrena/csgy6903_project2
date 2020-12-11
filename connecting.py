import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')

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
print(aes_public_numbers.y)

peer_aes_public_numbers = dh.DHPublicNumbers(int_from_bytes(peer_aes_public_y), pn)
peer_aes_public_key = peer_aes_public_numbers.public_key()

aes_shared_key = aes_private_key.exchange(peer_aes_public_key)
print(aes_shared_key)