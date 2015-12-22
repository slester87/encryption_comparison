from M2Crypto.RC4 import RC4
from M2Crypto import EVP
from M2Crypto import RSA
from salsa20 import XSalsa20_xor

from os import urandom
import sys

from test_common import pad_the_file, make_symm_key
from test_common import name_ciphertext_file, name_plaintext_file

def run_tests(plaintext_input_file):
    padded_input_file = plaintext_input_file + ".padded"
    pad_the_file(plaintext_input_file, padded_input_file)
    test_all_block_ciphers(padded_input_file)
    test_stream_ciphers(plaintext_input_file)
    test_asymmetric_rsa(padded_input_file)
    test_hashes(plaintext_input_file)


def test_all_block_ciphers(padded_input_file):
    sixteen_byte_key = make_symm_key(str(padded_input_file), 16)
    eight_byte_key = make_symm_key(str(reversed(padded_input_file)), 8)

    block_modes = ['ecb','cbc','cfb','ofb']
    cipher_algs = ['aes_256', 'des_ede3', 'bf']

    for one_cipher in cipher_algs:
        for one_mode in block_modes:
            test_one_block_cipher(one_cipher, one_mode, sixteen_byte_key, eight_byte_key, padded_input_file)


def test_one_block_cipher(one_cipher, one_mode, sixteen_byte_key, eight_byte_key, padded_input_file):
    alg_str = one_cipher + "_" + one_mode
    ek = EVP.Cipher(alg=alg_str, key=sixteen_byte_key, iv=eight_byte_key, op=1)
    dk = EVP.Cipher(alg=alg_str, key=sixteen_byte_key, iv=eight_byte_key, op=0)

    with open(padded_input_file, 'rb') as in_file:
        with open(name_ciphertext_file("M2", one_cipher, one_mode), 'wb') as out_file:
            while 1:
                buf = in_file.read()
                if not buf: break
                out_file.write(ek.update(buf))
            out_file.write(ek.final())
    with open(name_ciphertext_file("M2", one_cipher, one_mode), 'rb') as in_file:
        with open(name_plaintext_file("M2", one_cipher, one_mode), 'wb') as out_file:
            while 1:
                buf = in_file.read()
                if not buf: break
                out_file.write(dk.update(buf))
            out_file.write(dk.final())

def test_stream_ciphers(plaintext_input_file):
    test_stream_cipher_rc4(plaintext_input_file)
    test_stream_cipher_xsalsa(plaintext_input_file)

def test_stream_cipher_rc4(plaintext_input_file):
    rc4_key = make_symm_key(str(plaintext_input_file),16)
    ek = RC4()
    ek.set_key(rc4_key)
    dk = RC4()
    dk.set_key(rc4_key)
    with open(plaintext_input_file, 'rb') as in_file:
        with open(name_ciphertext_file("M2", "rc4", "rc4"), 'wb') as out_file:
            while 1:
                buf = in_file.read()
                if not buf: break
                out_file.write(ek.update(buf))
            out_file.write(ek.final())
    with open(name_ciphertext_file("M2", "rc4", "rc4"), 'rb') as in_file:
        with open(name_plaintext_file("M2", "rc4", "rc4"), 'wb') as out_file:
            while 1:
                buf = in_file.read()
                if not buf: break
                out_file.write(dk.update(buf))
            out_file.write(dk.final())

def test_stream_cipher_xsalsa(plaintext_input_file):
    iv = urandom(24)
    key = urandom(32)

    with open(plaintext_input_file, 'rb') as in_file:
        with open(name_ciphertext_file("M2", "xsalsa", "xsalsa"), 'wb') as out_file:
            while 1:
                buf = in_file.read()
                if not buf: break
                out_file.write(XSalsa20_xor(buf, iv, key))
    with open(name_ciphertext_file("M2", "xsalsa", "xsalsa"), 'rb') as in_file:
        with open(name_plaintext_file("M2", "xsalsa", "xsalsa"), 'wb') as out_file:
            while 1:
                buf = in_file.read()
                if not buf: break
                out_file.write(XSalsa20_xor(buf, iv, key))

def test_asymmetric_rsa(padded_input_file):

    def rsa_gen_callback(*args): pass

    rsa = RSA.gen_key(2048, 65537, rsa_gen_callback)
    padding = getattr(RSA, 'pkcs1_padding')
    with open(padded_input_file, 'rb') as in_file:
        with open(name_ciphertext_file("M2", "rsa", "rsa"), 'wb') as out_file:
            while 1:
                buf = in_file.read(64)
                if not buf: break
                # Intermediate variable used to sense size of chunk for decrypt
                outbuf = rsa.public_encrypt(buf, padding)
                out_file.write(outbuf)
    with open(name_ciphertext_file("M2", "rsa", "rsa"), 'rb') as in_file:
        with open(name_plaintext_file("M2", "rsa", "rsa"), 'wb') as out_file:
            while 1:
                buf = in_file.read(256)
                if not buf: break
                out_file.write(rsa.private_decrypt(buf, padding))

def test_hashes(plaintext_input_file):

    sha256 = EVP.MessageDigest('sha256')
    with open(plaintext_input_file, 'rb') as in_file:
        while 1:
            buf = in_file.read(64)
            if not buf: break
            sha256.update(buf)
        sha256.final()

    md5 = EVP.MessageDigest('md5')
    with open(plaintext_input_file, 'rb') as in_file:
        while 1:
            buf = in_file.read(64)
            if not buf: break
            md5.update(buf)
        md5.final()



run_tests(sys.argv[1])
