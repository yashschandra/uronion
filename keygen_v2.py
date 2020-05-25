import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64
import sys
import datetime

# class compatible with private numbers used by cryptography module
class PrivateNumbers:

    def egcd(self, a, b):
        if a == 0:
            return (b, 0, 1)
        g, y, x = self.egcd(b%a,a)
        return (g, x - (b//a) * y, y)

    # find inverse modulus 
    def modinv(self, a, m):
        g, x, _ = self.egcd(a, m)
        if g != 1:
            raise Exception('No modular inverse')
        return x%m

    # class compatible with public numbers used by cryptography module
    class PublicNumbers:
        def __init__(self, n, e):
            self.n = n
            self.e = e

    def __init__(self, p, q, iqmp, n, e):
        # (d*e) % ((p-1)*(q-1)) = 1
        d = self.modinv(e, (p-1)*(q-1))
        self.p = p
        self.q = q
        self.d = d
        self.dmp1 = d%(p-1)
        self.dmq1 = d%(q-1)
        self.iqmp = iqmp
        self.public_numbers = PrivateNumbers.PublicNumbers(n, e)

# generate new rsa key pair
def get_rsa_key(e, s):
    return rsa.generate_private_key(public_exponent = e, key_size = s, backend = default_backend())

# generate onion address from public bytes
def find_onion(public_bytes):
    # initialise sha1
    sha_1 = hashlib.sha1()
    # get sha1 of public key
    sha_1.update(public_bytes)
    # get digest of public key
    digest = sha_1.digest()
    # base32 encode digest
    b32 = base64.b32encode(digest).decode('utf-8')
    # take first 16 bytes and append .onion
    return str(b32[:16].lower()) + '.onion'

# get public part  of private key
def get_public_part(private_key):
    # get public key from private key
    public_key = private_key.public_key()
    # get public key as bytes
    public_bytes = public_key.public_bytes(encoding = serialization.Encoding.PEM, format = serialization.PublicFormat.PKCS1).decode('utf-8')
    # remove first and last line (key header and footer)
    return ''.join(public_bytes.splitlines()[1:-1])

# match if onion address starts with desired prefix
def match(desired, onion):
    return onion.startswith(desired)

# get private key as pem encoded string
def get_private_key_str(private_key):
    pem = private_key.private_bytes(encoding = serialization.Encoding.PEM, format = serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
    return pem.decode('utf-8')

# print info
def print_info(*argv):
    for a in argv:
        print(a)

# generate new private key with old private key and new public exponent
def change_public_exponent(private_key, e):
    try:
        # get old private key numbers
        private_numbers = private_key.private_numbers()
        # generate new private key numbers (new d and e)
        new_private_numbers = PrivateNumbers(private_numbers.p, private_numbers.q, private_numbers.iqmp, private_numbers.public_numbers.n, e)
        # return private key generated using new numbers
        return default_backend().load_rsa_private_numbers(new_private_numbers)
    except:
        # if exception occurs (finding enverse modulus fails)
        return None


# write text to a file
def write_text_to_file(path, text):
    with open(path, 'w+') as text_file:
        text_file.write(text)

def run(desired):
    # key size 1024 bytes
    s = 0x400
    # run forever
    # this loop will break when we will find a matching onion address and key
    while True:
        # public exponent 65537 (3 bytes)
        e = 0x10001
        # generate private and public key pair
        private_key = get_rsa_key(e, s)
        # get public part of private key
        public_part = get_public_part(private_key)
        # decode public part
        public_bytes = bytearray(base64.b64decode(public_part))
        # size of public exponent always 3 bytes
        while e > 0x7fff:
            # change public exponent in original public key (last 3 bytes changed)
            new_public_bytes = public_bytes[:-3] + bytearray.fromhex(hex(e)[2:].zfill(6))
            # generate onion address from public key
            onion = find_onion(new_public_bytes)
            # check if there is a match
            if match(desired, onion):
                # generate new private key with new public exponent
                private_key = change_public_exponent(private_key, e)
                # if private key found
                if private_key is not None:
                    # get private key as string
                    key_str = get_private_key_str(private_key)
                    # write private key to file
                    write_text_to_file('hidden_service/private_key', key_str)
                    # print generated onion address 
                    print_info(onion)
                    return
            # decrement exponent by 2, always keep it odd
            e = e - 2

if __name__ == '__main__':
    desired = sys.argv[1]
    run(desired)