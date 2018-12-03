#!/usr/bin/env python

import os
import time
import json
from pytlv import TLV
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
    load_pem_private_key, load_pem_public_key
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)

global privkey, pubkey, privpem, pubpem
global peerpubpem, peerpubkey
global encryptkey

post_log_path = 'post.log'


def post_log(data):
    with open(post_log_path, 'a') as outfile:
        outfile.write('[%s]\n' % time.strftime('%c'))
        outfile.write(data)
        outfile.write('\n\n\n')


# type 1: IV, type 2: tag, type 0: ciphertext
tlv = TLV.TLV(['0', '1', '2'])

# tlv = TLV(['84', 'A5']) # provide the possible tag values
# tlv.parse('840E315041592E5359532E4444463031A5088801025F2D02656E')
# >>> {'84': '315041592E5359532E4444463031', 'A5': '8801025F2D02656E'}


def encrypt(key, iv, plaintext):
    # Construct an AES-GCM Cipher object with the given key and a
    # randomly generated IV.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    # Encrypt the plaintext and get the associated ciphertext.
    # GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (iv, ciphertext, encryptor.tag)


def decrypt(key, iv, ciphertext, tag):
    # Construct a Cipher object, with the key, iv, and additionally the
    # GCM tag used for authenticating the message.
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    # Decryption gets us the authenticated plaintext.
    # If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()


key = 'zhaochao' * 2
# Generate a random 96-bit IV.
iv = os.urandom(12)

iv, ciphertext, tag = encrypt(
    key,
    iv,
    b"a secret message!",
)

print(decrypt(
    key,
    iv,
    ciphertext,
    tag
))


class DashRequestHandler(BaseHTTPRequestHandler, object):

    def __print_info__(self):
        print("headers: %s" % self.headers)

    def __get_root__(self):
        self.send_response(200)
        content_type = self.headers.getheader('Content-Type')
        print('Content Type is: %s' % content_type)
        if content_type.startswith('application/json'):
            inpath = 'index.json'
        else:
            inpath = 'index.html'
        with open(inpath, 'r') as infile:
            data = infile.read()
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers',
                         'Authorization,Content-Type,Accept,Origin,User-Agent,'
                         'DNT,Cache-Control,X-Mx-ReqToken,Keep-Alive,'
                         'X-Requested-With,If-Modified-Since')
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(data)

    def __get_pubkey__(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        dictdata = {'publicKey': pubpem}
        data = json.dumps(dictdata)
        self.send_header('Content-Length', len(data))
        self.end_headers()
        self.wfile.write(data)

    def __post_pubkey__(self, data):
        global peerpubkey, peerpubpem, encryptkey
        dictdata = json.loads(data)
        peerpubpem = dictdata['publicKey'].encode()
        print('android post pubkey:\n%s' % peerpubpem)
        peerpubkey = load_pem_public_key(peerpubpem, backend=default_backend())
        sharedkey = privkey.exchange(ec.ECDH(), peerpubkey)
        print('shared key: %s' % sharedkey)
        encryptkey = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'encryption key for network',
            backend=default_backend()
        ).derive(sharedkey)
        print('encryption key: %s' % encryptkey)

    def __post_locale__(self, data):
        print('android post locale:\n%s' % data)

    def __post_stoken__(self, data):
        pass

    def __post_network__(self, data):
        pass

    def do_GET(self):
        self.__print_info__()
        print self.path
        if self.path is '/':
            self.__get_root__()
        elif self.path.startswith('/pubkey'):
            self.__get_pubkey__()
        else:
            self.send_response(404)

    def do_POST(self):
        self.__print_info__()
        content_length = int(self.headers.getheader('Content-Length', 0))
        data = self.rfile.read(content_length)
        if self.path.startswith('/pubkey'):
            self.__post_pubkey__(data)
        elif self.path.startswith('/locale'):
            self.__post_locale__(data)
        elif self.path.startswith('/stoken'):
            self.__post_stoken__(data)
        elif self.path.startswith('/network'):
            self.__post_network__(data)
        post_log(data)
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', 0)
        self.end_headers()


def start_server():
    print("Start Dash Button Server...")
    DashRequestHandler.protocol_version = 'HTTP/1.0'
    httpd = HTTPServer(('0.0.0.0', 80), DashRequestHandler)
    httpd.serve_forever()


def gen_write_keys(privkey_filename, pubkey_filename):
    global privkey, pubkey, privpem, pubpem
    # secp256r1 equals to NIST P-256, P-256, prime256v1
    privkey = ec.generate_private_key(ec.SECP256R1(), default_backend())
    privpem = privkey.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    pubkey = privkey.public_key()
    pubpem = pubkey.public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    with open(privkey_filename, 'w') as outfile:
        outfile.write(privpem)
    with open(pubkey_filename, 'w') as outfile:
        outfile.write(pubpem)
    print('New key generated. Write to %s and %s' %
          (privkey_filename, pubkey_filename))


def read_keys(privkey_filename, pubkey_filename=None):
    global privkey, pubkey, privpem, pubpem
    print('Read keys from %s and %s' % (privkey_filename, pubkey_filename))
    with open(privkey_filename, 'r') as infile:
        privpem = infile.read()
    privkey = load_pem_private_key(
        privpem, password=None, backend=default_backend())
    if pubkey_filename is None:
        pubkey = privkey.public_key()
        pubpem = pubkey.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    else:
        with open(pubkey_filename, 'r') as infile:
            pubpem = infile.read()
        pubkey = load_pem_public_key(pubpem, backend=default_backend())


def get_keys(privkey_filename, pubkey_filename):
    if 'genkey' in os.sys.argv:
        gen_write_keys(privkey_filename, pubkey_filename)
    else:
        read_keys(privkey_filename, pubkey_filename)


if __name__ == '__main__':
    privkey_filename = 'priv.pem'
    pubkey_filename = 'pub.pem'
    get_keys(privkey_filename, pubkey_filename)
    print('private key:\n%s\npublic key:\n%s' % (privpem, pubpem))
    start_server()
