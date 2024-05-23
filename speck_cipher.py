#
# IMPLEMENTATION OF SPECK64/128 CIPHER IN PYTHON PROGRAMMING LANGUAGE
#
# Key features of the algorithm:
# block size: 64-bits (in 2 32-bits words)
# key size: 128-bits (in 4 32-bits words)
# Nr. of rounds: 27
# Word size: 32-bits
#
# Written by Leonardo Miliani (2023)
# Release under the terms of the CC license BY-NC-SA 4.0 or later
# Code revisions:
# 2024/05/23

# import module
from sys import argv
import time
from speck_cipher_ofb_stream import *
import os.path

FILENAME = "sample.txt"

# class instantiation
speck = SpeckCipher()

# main code
def main(arguments):
    print("SPECK64/128 CIPHER")
    
    # ask for key
    tmpKey = input('Enter key (16 chars, no spaces): ')
    tmpKey.replace(' ', '')
    if (tmpKey == ''):
        return
    # pad the key to 16 chars
    key = speck.padding(tmpKey, 16, truncate=True)
    keyLst = list(key)
    keyList = [ord(x) for x in keyLst]

    # ask for file
    tmpFile = input('File to be encrypted (return = sample file): ')
    if tmpFile == '':
        # no file? set to open the sample file
        tmpFile = FILENAME
        if (not os.path.isfile(tmpFile)):
            #if it doesn't exist yet, it creates it
            f = open(tmpFile, "w")
            f.write("Sample text")
            f.flush()
            f.close()
            print('Sample file not found - created')
    # check if the input file exists
    if (not os.path.exists(tmpFile)):
        print('{} doesn\'t exist.'.format(tmpFile))
        return
    # check if the file is a valid file
    if (not os.path.isfile(tmpFile)):
        print('{} isn\'t a valide file.'.format(tmpFile))
        return
    # start encryption
    print(f'Encrypting {tmpFile}...')
    time1 = time.time()
    speck.encryptFile(tmpFile, keyList)
    time2 = time.time()
    print('File encrypted. Time elapsed: {}'.format(time2-time1))
    # start decryption
    print('Now decrypting...')
    time1 = time.time()
    speck.decryptFile(tmpFile, keyList)
    time2 = time.time()
    print('File decrypted. Time elapsed: {}'.format(time2-time1))
    
# run only when explicitely launched
if __name__ == "__main__":
    main(argv)
    print("\nTERMINATED")
