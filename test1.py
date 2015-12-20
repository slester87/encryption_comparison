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
from Crypto.Cipher import PKCS1_v1_5

# Hashes to test
from Crypto.Hash import SHA256
from Crypto.Hash import MD5

# Utility
import time
from Crypto import Random
import random
import datetime
import sys
import shutil
from os import path


def run_tests(plaintext_input_file):
    padded_input_file = plaintext_input_file + ".padded"
    pad_the_file(plaintext_input_file, padded_input_file)
    test_all_block_ciphers(padded_input_file)
    test_stream_ciphers(plaintext_input_file)
    test_asymmetric(padded_input_file)
    '''test_hashes(plaintext_input_file)'''


def pad_the_file(plaintext_input_file, padded_input_file):
    filesize = path.getsize(plaintext_input_file)
    shutil.copy(plaintext_input_file, padded_input_file)

    if not (filesize % 16 == 0 or filesize == 0):
        file_dif = 16 - (filesize % 16)

        # print("filesize " + str(filesize) + " dif is " + str(file_dif) + "\n")
        with open(padded_input_file, "ab") as out_f:
            out_f.seek(len(plaintext_input_file))
            diff_bytes = bytearray(file_dif)
            out_f.write(diff_bytes)

    filesize_padded = path.getsize(padded_input_file)

    # print("padded is " + str(filesize_padded)+ "\n\n")


def test_all_block_ciphers(file):
    # Todo: time the encryption and decryption of file and record results
    sixteen_byte_key = make_key(str(file), 16)
    eight_byte_key = make_key(str(reversed(file)), 8)

    test_block_cipher(AES, "AES", file, sixteen_byte_key, sixteen_byte_key)
    test_block_cipher(DES3, "TripleDes", file, sixteen_byte_key, eight_byte_key)
    test_block_cipher(Blowfish, "BlowFish", file, sixteen_byte_key, eight_byte_key)


def test_block_cipher(alg, algstr, file, key, iv):
    modes = [alg.MODE_ECB, alg.MODE_CBC, alg.MODE_CFB, alg.MODE_OFB]

    for mode in modes:
        start = datetime.datetime.now()

        block_encrypt(key, file, alg, algstr, mode, iv)
        finish = datetime.datetime.now()
        elapsed = finish - start
        modename = ""
        if mode == alg.MODE_ECB:
            modename += "ECB"
        elif mode == alg.MODE_CBC:
            modename += "CBC"
        elif mode == alg.MODE_CFB:
            modename += "CFB"
        else:
            modename += "OFB"
        print("Encrypting " + str(file) + " with " + algstr + " mode " + modename + " took " + str(
                elapsed) + " seconds. ")

        start = datetime.datetime.now()
        block_decrypt(key, alg, algstr, mode, iv)
        finish = datetime.datetime.now()
        elapsed = finish - start
        modename = ""
        if mode == alg.MODE_ECB:
            modename += "ECB"
        elif mode == alg.MODE_CBC:
            modename += "CBC"
        elif mode == alg.MODE_CFB:
            modename += "CFB"
        else:
            modename += "OFB"
        print("Decrypting " + str(file) + " with " + algstr + " mode " + modename + " took " + str(
                elapsed) + " seconds. \n\n")


def block_encrypt(key, plaintext_input_file, alg, algname, mode, init_vector):
    cipher = alg.new(key, mode, IV=init_vector)
    # Todo: end timer
    with open(plaintext_input_file, 'rb') as f:
        with open("ciphertext of " + str(algname) + " mode # " + str(mode) + ".txt", 'wb') as g:
            g.write(cipher.encrypt(f.read()))


def block_decrypt(key, alg, algname, mode, init_vector):
    cipher = alg.new(key, mode, IV=init_vector)
    with open("ciphertext of " + str(algname) + " mode # " + str(mode) + ".txt", 'rb') as f:
        with open("plaintext of " + str(algname) + " mode # " + str(mode) + ".txt", "wb") as g:
            g.write(cipher.decrypt(f.read()))


def test_stream_ciphers(file):
    # ARC4
    nonce = Random.new().read(16)
    key = make_key(b'str(file)' + nonce, 256)
    cipher = ARC4.new(key)
    with open(file, 'rb') as f:
        with open("ciphertext of " + "ARC4" + ".txt", 'wb') as g:
            start = datetime.datetime.now()
            g.write(cipher.encrypt(f.read()))
            finish = datetime.datetime.now()
            elapsed = finish - start
            print("Encrypting " + str(file) + " with " + "ARC4" + " took " + str(elapsed) + " seconds. ")

    cipher = ARC4.new(key)
    with open("ciphertext of " + "ARC4" + ".txt", 'rb') as f:
        with open("plaintext of ARC4.txt", 'wb') as g:
            start = datetime.datetime.now()
            g.write(cipher.decrypt(f.read()))
            finish = datetime.datetime.now()
            elapsed = finish - start
            print("Decrypting " + str(file) + " with " + "ARC4" + " took " + str(elapsed) + " seconds. \n\n ")

    # XOR
    key = make_key(key, 32)
    cipher = XOR.new(key)
    with open(file, 'rb') as f:
        with open("ciphertext of " + "XOR" + ".txt", 'wb') as g:
            start = datetime.datetime.now()
            g.write(cipher.encrypt(f.read()))
            finish = datetime.datetime.now()
            elapsed = finish - start
            print("Encrypting " + str(file) + " with " + "XOR" + " took " + str(elapsed) + " seconds. ")

    cipher = XOR.new(key)
    with open("ciphertext of " + "XOR" + ".txt", 'rb') as f:
        with open("plaintext of XOR.txt", 'wb') as g:
            start = datetime.datetime.now()
            g.write(cipher.decrypt(f.read()))
            finish = datetime.datetime.now()
            elapsed = finish - start
            print("Decrypting " + str(file) + " with " + "XOR" + " took " + str(elapsed) + " seconds. \n\n")


def test_asymmetric(file):
    # RSA
    from Crypto.PublicKey import RSA
    new_key = RSA.generate(2048, e=65537)
    public_key = new_key.publickey()
    private_key = new_key
    with open(file,'rb') as f:
        h = SHA256.new(f.read())

    with open(file, 'rb') as f:
        with open("ciphertext of RSA.txt", 'wb') as g:

            start = datetime.datetime.now()
            cipher = PKCS1_v1_5.new(public_key)

            bytes_read = f.read(64)
            while not (len(bytes_read) == 0):
                g.write(cipher.encrypt(bytes_read))
                bytes_read = f.read(64)
            g.write(cipher.encrypt(h.digest()))

            finish = datetime.datetime.now()
            elapsed = finish - start
            print("Encrypting " + str(file) + " with " + "RSA" + " took " + str(elapsed) + " seconds. ")

    with open("ciphertext of RSA.txt", 'rb') as f:
        with open("plaintext of RSA.txt", 'wb') as g:

            start = datetime.datetime.now()
            dsize = SHA256.digest_size
            sentinel = Random.new().read(15 + dsize)
            cipher = PKCS1_v1_5.new(private_key)
            bytes_read = f.read(64)

            while not (len(bytes_read) == 0):

                g.write(cipher.decrypt(bytes_read, bytes(0)))
                bytes_read = f.read(64)

            finish = datetime.datetime.now()
            elapsed = finish - start
            print("Decrypting " + str(file) + " with " + "RSA" + " took " + str(elapsed) + " seconds. ")




def test_hashes(file):
    return True


def make_key(salt, key_size):
    m = SHA256.new()
    m.update(str(datetime.datetime.now().second).encode('utf-8'))
    m.update((m.hexdigest() + str(Random.new().read(16)) + str(salt)).encode('utf-8'))

    return m.hexdigest()[0:key_size]


run_tests(sys.argv[1])
