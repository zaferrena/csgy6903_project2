import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def int_from_bytes(xbytes: bytes) -> int:
    return int.from_bytes(xbytes, 'big')

parameters = dh.generate_parameters(generator=2, key_size=2048)
pn = parameters.parameter_numbers()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((socket.gethostname(), 1234))
s.listen(5)

clientsocket, address = s.accept()
print("Connection to:  ", address)
clientsocket.send(int_to_bytes(pn.p))

aes_private_key = parameters.generate_private_key()
aes_public_key = aes_private_key.public_key()
aes_public_numbers = aes_public_key.public_numbers()

clientsocket.send(int_to_bytes(aes_public_numbers.y))
peer_aes_public_y = clientsocket.recv(2048)
print(aes_public_numbers.y)

peer_aes_public_numbers = dh.DHPublicNumbers(int_from_bytes(peer_aes_public_y), pn)
peer_aes_public_key = peer_aes_public_numbers.public_key()

aes_shared_key = aes_private_key.exchange(peer_aes_public_key)
print(aes_shared_key)