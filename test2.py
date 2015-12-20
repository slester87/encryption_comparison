# Block Ciphers to test
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Cipher import Blowfish

# Stream Ciphers to test
from Crypto.Cipher import ARC4
from Crypto.Cipher import XOR

# Asymmetric Key to test
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ElGamal

# Hashes to test
from Crypto.Hash import SHA256
from Crypto.Hash import MD5

# Utility
import timeit
import datetime
import sys
import shutil
from os import path


def run_tests(plaintext_input_file):
    padded_input_file = plaintext_input_file + ".padded"
    pad_the_file(plaintext_input_file, padded_input_file)
    test_all_block_ciphers(padded_input_file)
    '''test_stream_ciphers(file)
    test_asymmetric(file)
    test_hashes(file)'''


def pad_the_file(plaintext_input_file, padded_input_file):
    filesize = path.getsize(plaintext_input_file)
    shutil.copy(plaintext_input_file, padded_input_file)

    if not (filesize % 16 == 0 or filesize == 0):
        file_dif = 16 - (filesize % 16)

        print("filesize " + str(filesize) + " dif is " + str(file_dif))
        with open(padded_input_file, "ab") as out_f:
            out_f.seek(len(plaintext_input_file))
            diff_bytes = bytearray(file_dif)
            out_f.write(diff_bytes)

    filesize_padded = path.getsize(padded_input_file)

    print("padded is " + str(filesize_padded))


def test_all_block_ciphers(file):
    # Todo: time the encryption and decryption of file and record results
    sixteen_byte_key = make_key(str(file), 16)
    eight_byte_key = make_key(str(reversed(file)), 8)


    test_block_cipher(AES, "AES", file, sixteen_byte_key, sixteen_byte_key)
    test_block_cipher(DES3, "TripleDes", file, sixteen_byte_key, eight_byte_key)
    test_block_cipher(Blowfish, "BlowFish", file, sixteen_byte_key, eight_byte_key)


def test_block_cipher(alg,algstr, file, key, iv):
    modes = [alg.MODE_ECB, alg.MODE_CBC, alg.MODE_CFB, alg.MODE_OFB]

    for mode in modes:

        encrypt(key, file, alg, algstr, mode, iv)

        decrypt(key, alg, algstr, mode, iv)


def encrypt(key, plaintext_input_file, alg, algname, mode, init_vector):
    cipher = alg.new(key, mode, IV=init_vector)
    # Todo: end timer
    with open(plaintext_input_file, 'rb') as f:
        with open("ciphertext of " + str(algname) + " mode # " + str(mode) + ".txt", 'wb') as g:
            g.write(cipher.encrypt(f.read()))


def decrypt(key, alg, algname, mode, init_vector):
    cipher = alg.new(key, mode, IV=init_vector)
    with open("ciphertext of " + str(algname) + " mode # " + str(mode) + ".txt", 'rb') as f:
        with open("plaintext of " + str(algname)+ " mode # " + str(mode) + ".txt", "wb") as g:
            g.write(cipher.decrypt(f.read()))


def test_stream_ciphers(file):
    return True


def test_asymmetric(file):
    return True


def test_hashes(file):
    return True


def make_key(salt, key_size):
    m = SHA256.new()
    # print(datetime.datetime.now().second)
    m.update(str(datetime.datetime.now().second).encode('utf-8'))
    m.update((m.hexdigest() + str(reversed(salt)) + str(salt)).encode('utf-8'))

    return m.hexdigest()[0:key_size]


run_tests(sys.argv[1])
