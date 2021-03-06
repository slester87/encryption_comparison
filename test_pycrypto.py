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
from Crypto.Random import random
from Crypto.Util.number import GCD
import datetime
import sys


# test support  stuff
from test_common import pad_the_file, make_symm_key
from test_common import name_ciphertext_file, name_plaintext_file

def run_tests(plaintext_input_file):
    padded_input_file = plaintext_input_file + ".padded"
    pad_the_file(plaintext_input_file, padded_input_file)
    test_all_block_ciphers(padded_input_file)
    test_stream_ciphers(plaintext_input_file)
    test_asymmetric_rsa(padded_input_file)
    test_asymmetric_elgamal(padded_input_file)
    test_hashes(plaintext_input_file)


def test_all_block_ciphers(file):
    sixteen_byte_key = make_symm_key(str(file), 16)
    eight_byte_key = make_symm_key(str(reversed(file)), 8)

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
        with open("plaintext of " + str(algname) + " mode # " + str(mode) + ".jpg", "wb") as g:
            g.write(cipher.decrypt(f.read()))


def test_stream_ciphers(file):
    # ------------------------------------------ ARC4 -------------------------------------------------------------
    nonce = Random.new().read(16)
    key = make_symm_key(b'str(file)' + nonce, 256)
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
        with open("plaintext of ARC4.jpg", 'wb') as g:
            start = datetime.datetime.now()
            g.write(cipher.decrypt(f.read()))
            finish = datetime.datetime.now()
            elapsed = finish - start
            print("Decrypting " + str(file) + " with " + "ARC4" + " took " + str(elapsed) + " seconds. \n\n ")

    # ----------------------------------------- XOR ---------------------------------------------------------------
    key = make_symm_key(key, 32)
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
        with open("plaintext of XOR.jpg", 'wb') as g:
            start = datetime.datetime.now()
            g.write(cipher.decrypt(f.read()))
            finish = datetime.datetime.now()
            elapsed = finish - start
            print("Decrypting " + str(file) + " with " + "XOR" + " took " + str(elapsed) + " seconds. \n\n")


def test_asymmetric_rsa(file):
    # ----------------------------------------- RSA --------------------------------------------------------------
    start_making_keys = datetime.datetime.now()
    rsa_key = RSA.generate(2048, e=65537)
    public_key = rsa_key.publickey()
    private_key = rsa_key
    finish_making_keys = datetime.datetime.now()
    elapsed_keys = finish_making_keys - start_making_keys

    print("Keying " + str(file) + " with " + "RSA" + " took " + str(
            elapsed_keys) + " seconds. ")

    # --- encryption ---
    with open(file, 'rb') as f:
        with open("ciphertext of RSA.txt", 'wb') as g:
            start = datetime.datetime.now()
            cipher = PKCS1_v1_5.new(public_key)

            bytes_read = f.read(245)

            while not (len(bytes_read) == 0):
                g.write(cipher.encrypt(bytes_read))
                bytes_read = f.read(245)

            finish = datetime.datetime.now()
            elapsed = finish - start
            print("Encrypting " + str(file) + " with " + "RSA" + " took " + str(elapsed) + " seconds. ")
    # --- decryption ---
    with open("ciphertext of RSA.txt", 'rb') as f:
        with open("plaintext of RSA.jpg", 'wb') as g:
            start = datetime.datetime.now()
            dsize = SHA256.digest_size
            sentinel = Random.new().read(dsize)
            cipher = PKCS1_v1_5.new(private_key)
            bytes_read = f.read(256)  # include the digest size (32)

            while not (len(bytes_read) == 0):
                g.write(cipher.decrypt(bytes_read, sentinel=sentinel))
                bytes_read = f.read(256)

            finish = datetime.datetime.now()
            elapsed = finish - start
            print(
                    "Decrypting " + str(file) + " with " + "RSA" + " took " + str(
                            elapsed) + " seconds.\n\n")


            # -------------------------------------- ElGamal -----------------------------------------------------------


def test_asymmetric_elgamal(file):
    start = datetime.datetime.now()
    # generate 2 ELGAMAL key pair
    rpool = Random.new()
    Random.atfork()
    private_key = ElGamal.generate(512, rpool.read)
    public_key = private_key.publickey()


    # generate for each encryption session new K
    while 1:
        K = random.StrongRandom().randint(1, private_key.p - 1)
        if GCD(K, private_key.p - 1) == 1: break
    print("K for encrypt: " + str(K))
    finish_keys = datetime.datetime.now()
    keys_elapsed = finish_keys - start

    print("Keying " + str(file) + " with " + "ElGamal" + " took " + str(
            keys_elapsed) + " seconds. ")

    # --- encryption ---
    with open(file, 'rb') as f:
        with open("ciphertext of ElGamal.txt", 'wb') as g:
            start = datetime.datetime.now()

            bytes_read = f.read(54)

            while not (len(bytes_read) == 0):
                # pyCrypto's ElGamal's implementation appears to be broken:
                # print("original:  " + str(bytes_read))
                ciphertext = public_key.encrypt(bytes_read,K)

                g.write(ciphertext[0])
                g.write(ciphertext[1])

                # print("decrypted: " + str(local_plaintext))
                bytes_read = f.read(54)

            finish = datetime.datetime.now()
            encrypt_elapsed = finish - start

            print("Encrypting " + str(file) + " with " + "ElGamal" + " took " + str(
                    encrypt_elapsed) + " seconds. ")
    # --- decryption ---
    with open("ciphertext of ElGamal.txt", 'rb') as f:
        with open("plaintext of ElGamal.jpg", 'wb') as g:
            start = datetime.datetime.now()

            bytes_read = f.read(64) # include the digest size (32)
            bytes_read_2 = f.read(64)  # include the digest size (32)

            while not (len(bytes_read) == 0):
                plaintext = private_key.decrypt((bytes_read, bytes_read_2))
                # print("plaintext: " + str(plaintext))
                g.write(plaintext)
                bytes_read = f.read(64)
                bytes_read_2 = f.read(64)  # include the digest size (32)

            finish = datetime.datetime.now()
            elapsed = finish - start
            print("Decrypting " + str(file) + " with " + "ElGamal" + " took " + str(
                    elapsed) + " seconds.\n\n ")


def test_hashes(file):
    # Time the hashing of a large file using cryptographically secure hash
    start = datetime.datetime.now()
    h = SHA256.new()
    with open(file, 'rb') as f:
        h.update(f.read())
    hash = h.hexdigest()
    finish = datetime.datetime.now()
    elapsed = finish - start
    print("Hashing " + str(file) + " with SHA256 took " + str(elapsed) + " seconds.\n ")
    print("With AES256, " + str(file) + " hashed to " + str(hash) + "\n\n")

    start = datetime.datetime.now()
    h = MD5.new()
    with open(file, 'rb') as f:
        h.update(f.read())
    hash2 = h.hexdigest()

    finish = datetime.datetime.now()
    elapsed = finish - start
    print("Hashing " + str(file) + " with MD5 took " + str(elapsed) + " seconds.\n ")
    print("With MD5, " + str(file) + " hashed to " + str(hash2) + "\n\n")



run_tests(sys.argv[1])
