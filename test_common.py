import shutil
import sys
from os import path

# Used for symmetric key generation
from Crypto.Hash import SHA256
from Crypto import Random
import datetime


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


def make_symm_key(salt, key_size):
    m = SHA256.new()
    m.update(str(datetime.datetime.now().second).encode('utf-8'))

    intermediate = (m.hexdigest() + str(Random.new().read(16)) + str(salt))
    if (sys.version_info[0] >= 3): intermediate = intermediate.encode("utf-8")

    m.update(intermediate)

    return m.hexdigest()[0:key_size]


def name_ciphertext_file(suite, alg, mode, ext="jpg"):
    return "ciphertext_of_" + str(suite) +"_" +str(alg) +"_"+ str(mode) +"."+ str(ext)

def name_plaintext_file(suite, alg, mode, ext="jpg"):
    return "plaintext_of_" + str(suite) +"_" +str(alg) +"_"+ str(mode) +"."+ str(ext)
