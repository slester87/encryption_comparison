from M2Crypto.RC4 import RC4
from M2Crypto import EVP
from M2Crypto import RSA
from salsa20 import XSalsa20_xor

from os import urandom
import sys
import datetime
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

    block_modes = ['ecb', 'cbc', 'cfb', 'ofb']
    cipher_algs = ['aes_256', 'des_ede3', 'bf']

    for one_cipher in cipher_algs:
        for one_mode in block_modes:
            test_one_block_cipher(one_cipher, one_mode, sixteen_byte_key, eight_byte_key, padded_input_file)


def test_one_block_cipher(one_cipher, one_mode, sixteen_byte_key, eight_byte_key, padded_input_file):
    alg_str = one_cipher + "_" + one_mode
    mk_start = datetime.datetime.now()  # stopwatch
    ek = EVP.Cipher(alg=alg_str, key=sixteen_byte_key, iv=eight_byte_key, op=1)
    dk = EVP.Cipher(alg=alg_str, key=sixteen_byte_key, iv=eight_byte_key, op=0)
    mk_elapsed = datetime.datetime.now() - mk_start  # stopwatch

    with open(padded_input_file, 'rb') as in_file:
        with open(name_ciphertext_file("M2", one_cipher, one_mode), 'wb') as out_file:
            encrypt_start = datetime.datetime.now()  # stopwatch
            while 1:
                buf = in_file.read()
                if not buf: break
                out_file.write(ek.update(buf))
            out_file.write(ek.final())

            encrypt_elapsed = datetime.datetime.now() - encrypt_start  # stopwatch

    with open(name_ciphertext_file("M2", one_cipher, one_mode), 'rb') as in_file:
        with open(name_plaintext_file("M2", one_cipher, one_mode), 'wb') as out_file:
            decrypt_start = datetime.datetime.now()  # stopwatch
            while 1:
                buf = in_file.read()
                if not buf: break
                out_file.write(dk.update(buf))
            out_file.write(dk.final())
            decrypt_elapsed = datetime.datetime.now() - decrypt_start  # stopwatch

    print("Encrypt with " + str(one_cipher) + " in " + str(one_mode) + " mode took " + str(
            mk_elapsed + encrypt_elapsed) + " seconds.")
    print("Decrypt with " + str(one_cipher) + " in " + str(one_mode) + " mode took " + str(
            mk_elapsed + decrypt_elapsed) + " seconds. \n\n")


def test_stream_ciphers(plaintext_input_file):
    test_stream_cipher_rc4(plaintext_input_file)
    test_stream_cipher_xsalsa(plaintext_input_file)


def test_stream_cipher_rc4(plaintext_input_file):
    mk_start = datetime.datetime.now()
    rc4_key = make_symm_key(str(plaintext_input_file), 16)
    ek = RC4()
    ek.set_key(rc4_key)
    dk = RC4()
    dk.set_key(rc4_key)
    mk_elapsed = datetime.datetime.now() - mk_start

    with open(plaintext_input_file, 'rb') as in_file:
        with open(name_ciphertext_file("M2", "rc4", "rc4"), 'wb') as out_file:
            enc_start = datetime.datetime.now()
            while 1:
                buf = in_file.read()
                if not buf: break
                out_file.write(ek.update(buf))
            out_file.write(ek.final())
            enc_elapsed = datetime.datetime.now() - enc_start
    with open(name_ciphertext_file("M2", "rc4", "rc4"), 'rb') as in_file:
        with open(name_plaintext_file("M2", "rc4", "rc4"), 'wb') as out_file:
            dec_start = datetime.datetime.now()
            while 1:
                buf = in_file.read()
                if not buf: break
                out_file.write(dk.update(buf))
            out_file.write(dk.final())
            dec_elapsed = datetime.datetime.now() - dec_start
    print("Encrypt with " + "RC4" + " took " + str(mk_elapsed + enc_elapsed) + " seconds.")
    print("Decrypt with " + "RC4" + " took " + str(mk_elapsed + dec_elapsed) + " seconds. \n\n")


def test_stream_cipher_xsalsa(plaintext_input_file):
    mk_start = datetime.datetime.now()
    iv = urandom(24)
    key = urandom(32)
    mk_elapsed = datetime.datetime.now() - mk_start
    with open(plaintext_input_file, 'rb') as in_file:
        with open(name_ciphertext_file("M2", "xsalsa", "xsalsa"), 'wb') as out_file:
            enc_start = datetime.datetime.now()
            while 1:
                buf = in_file.read()
                if not buf: break
                out_file.write(XSalsa20_xor(buf, iv, key))
                enc_elapsed = datetime.datetime.now() - enc_start
    with open(name_ciphertext_file("M2", "xsalsa", "xsalsa"), 'rb') as in_file:
        with open(name_plaintext_file("M2", "xsalsa", "xsalsa"), 'wb') as out_file:
            dec_start = datetime.datetime.now()
            while 1:
                buf = in_file.read()
                if not buf: break
                out_file.write(XSalsa20_xor(buf, iv, key))
            dec_elapsed = datetime.datetime.now() - dec_start
    print("Encrypt with " + "xsalsa" + " took " + str(mk_elapsed + enc_elapsed) + " seconds.")
    print("Decrypt with " + "xsalsa" + " took " + str(mk_elapsed + dec_elapsed) + " seconds. \n\n")


def test_asymmetric_rsa(padded_input_file):
    def rsa_gen_callback(*args):
        pass
    mk_rsa_keys_start = datetime.datetime.now()
    rsa = RSA.gen_key(2048, 65537, rsa_gen_callback)
    mk_rsa_keys_elapsed = datetime.datetime.now() - mk_rsa_keys_start
    print("Keying with " + "rsa" + " took " + str(mk_rsa_keys_elapsed) + " seconds.")

    padding = getattr(RSA, 'pkcs1_padding')
    with open(padded_input_file, 'rb') as in_file:
        with open(name_ciphertext_file("M2", "rsa", "rsa"), 'wb') as out_file:
            enc_start = datetime.datetime.now()
            while 1:
                buf = in_file.read(64)
                if not buf: break
                # Intermediate variable used to sense size of chunk for decrypt
                outbuf = rsa.public_encrypt(buf, padding)
                out_file.write(outbuf)
            enc_elapsed = datetime.datetime.now() - enc_start
    with open(name_ciphertext_file("M2", "rsa", "rsa"), 'rb') as in_file:
        with open(name_plaintext_file("M2", "rsa", "rsa"), 'wb') as out_file:
            dec_start = datetime.datetime.now()
            while 1:
                buf = in_file.read(256)
                if not buf: break
                out_file.write(rsa.private_decrypt(buf, padding))
            dec_elapsed = datetime.datetime.now() - dec_start
    print("Encrypt with " + "rsa" + " took " + str(enc_elapsed) + " seconds.")
    print("Decrypt with " + "rsa" + " took " + str(dec_elapsed) + " seconds. \n\n")

def test_hashes(plaintext_input_file):
    sha256 = EVP.MessageDigest('sha256')
    with open(plaintext_input_file, 'rb') as in_file:
        hash_start = datetime.datetime.now()
        while 1:
            buf = in_file.read(64)
            if not buf: break
            sha256.update(buf)
        sha256.final()
    hash_elapsed = datetime.datetime.now() - hash_start
    print("Hashing with sha256 took " + str(hash_elapsed) + " seconds.\n ")

    md5 = EVP.MessageDigest('md5')
    with open(plaintext_input_file, 'rb') as in_file:
        hash_start = datetime.datetime.now()
        while 1:
            buf = in_file.read(64)
            if not buf: break
            md5.update(buf)
        md5.final()
    hash_elapsed = datetime.datetime.now() - hash_start
    print("Hashing with md5 took " + str(hash_elapsed) + " seconds.\n\n ")


run_tests(sys.argv[1])
