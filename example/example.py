import pyrsaref
from hexdump import hexdump

""""
# Known-value test
rsa = pyrsaref.CryptRSA()

pub_key = bytes([0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC5, 0xF0, 0x0F, 0x14, 0x34, 0xA4, 0x98, 0x97, 0x82, 0x87, 0x11, 0x84, 0xEC, 0x0F, 0x59, 0xB2, 0xFA, 0x9C, 0x02, 0xD7, 0x1F, 0x91, 0x46, 0x73, 0x51, 0xFE, 0x24, 0x82, 0xF1, 0x1B, 0xB8, 0xA4, 0x75, 0x0B, 0x78, 0x51, 0x97, 0x0A, 0x80, 0x50, 0xA9, 0xCE, 0xF4, 0x97, 0x9A, 0x86, 0x0A, 0xEA, 0x58, 0xDB, 0x4B, 0x65, 0xFA, 0xA0, 0x2E, 0xF0, 0xBD, 0x99, 0xC4, 0xE4, 0x3C, 0xE4, 0x9E, 0x4F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01])

rsa.set_key(pub_key, pyrsaref.MODE_PUBLIC)
rsa.set_randstate(bytes([0x00, 0x00, 0x00, 0x00, 0x1a, 0xf3, 0xc6, 0xf5, 0xab, 0x90, 0x68, 0xe0, 0x11, 0x14, 0xc5, 0x8b, 0xf6, 0x54, 0x91, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0xd6, 0x00, 0x00, 0x00, 0x01, 0x01, 0x53, 0x00, 0x00, 0x00, 0x01]))

aes_key = bytes([0xAA] * 256)
rsa.encrypt(aes_key, pyrsaref.MODE_PUBLIC)


hexdump(rsa.get_data())
"""


s = pyrsaref.CryptRSA()
sr = pyrsaref.CryptRSA()

s.make_keys()

# Make a encrypted message on the server:
s.encrypt(b'TEST' * 64, pyrsaref.MODE_PRIVATE)
secret_message = s.get_data()
#hexdump(secret_message)

# "Send" server public key to client
pub_key = s.get_key(pyrsaref.MODE_PUBLIC)
sr.set_key(pub_key, pyrsaref.MODE_PUBLIC)

# Decrypt secret message from client receiver
sr.decrypt(secret_message, pyrsaref.MODE_PUBLIC)
hexdump(sr.get_data())
