#
# IMPLEMENTATION OF SPECK64/128 CIPHER IN DART PROGRAMMING LANGUAGE
#
# Key features of the algorithm:
# block size: 64-bits (in 2 32-bits words)
# key size: 128-bits (in 4 32-bits words)
# Nr. of rounds: 27
# Word size: 32-bits
#
# OFB cipher mode of operation
# This mode of operation manages files as streams of data
#
# Written by Leonardo Miliani (2023)
# Release under the terms of the CC license BY-NC-SA 4.0 or later

import os       # needed to access to filesystem
import secrets  # needed to generate random numbers


class SpeckCipher:
    ### Implementation of Speck64/128 Cipher
    BLOCK_SIZE = 64
    KEY_SIZE = 128
    ROUNDS = 27
    WORD_SIZE_N = 32
    KEY_WORDS_M = 4

    # encrypt a file
    def encryptFile(self, fileName, key):
        cipherText = [0, 0]
        plainText = [0, 0]
        # get roundkey from key
        roundKey = self.keySchedule(self.bytesToWord32(key))
        # create and store IV (initialization vector)
        intVect = [0, 0]
        intVect[0] = self.IV()
        intVect[1] = self.IV()
        dataBytes = self.word32ToBytes(intVect)
        # prepare output file
        fileOutput = open(fileName + '.enc', "wb")
        # write IV
        fileOutput.write(bytearray(dataBytes))
        # open input file
        fileSize = os.path.getsize(fileName)
        fileInput = open(fileName, "rb")
        blockSize = 8
        padding = -1
        # read blocks of 8 bytes
        for i in range(0, fileSize, blockSize):
            block = fileInput.read(blockSize)
            endIndex = i + blockSize
            endIndex = fileSize if endIndex > fileSize else endIndex
            # check if pad is necessary
            if len(block) < blockSize:
                padding = blockSize - (endIndex % blockSize)
                if padding != blockSize:
                    blck = self.padding(block, blockSize, pad = padding)
                    block = [ord(x) for x in blck]
            # encrypt the block and write it into the output file
            block_list = list(block)
            plainText = self.bytesToWord32(block_list)
            cipherText = self.encrypt(plainText, roundKey, intVect)
            encBlock = self.word32ToBytes(cipherText)
            fileOutput.write(bytearray(encBlock))
        # if file lenght is a mul of 8, add another block
        if padding == blockSize:
            block = [8] * blockSize
            plainText = self.bytesToWord32(block)
            cipherText = self.encrypt(plainText, roundKey, intVect)
            encBlock = self.word32ToBytes(cipherText)
            fileOutput.write(bytearray(encBlock))
        # close files
        fileOutput.flush()
        fileOutput.close()
        fileInput.close()


    def decryptFile(self, fileName, key):
        cipherText = [0, 0]
        plainText = [0, 0]
        # get roundkey from key
        roundKey = self.keySchedule(self.bytesToWord32(key))
        # prepare output file
        fileOutput = open(fileName + '.dec', "wb")
        # open input file
        fileSize = os.path.getsize(fileName + '.enc')
        fileInput = open(fileName + '.enc', "rb")
        blockSize = 8
        # create IV (initialization vector)
        intVect = [0, 0]
        for i in range(0, fileSize, blockSize):
            endIndex = i + blockSize
            endIndex = fileSize if endIndex > fileSize else endIndex
            block = list(fileInput.read(blockSize))
            if i == 0:
                # the first block contains the IV...
                intVect = self.bytesToWord32(block)
            else:
                # ...while the other ones normal data...
                cipherText = self.bytesToWord32(block)
                plainText = self.decrypt(cipherText, roundKey, intVect)
                decBlock = self.word32ToBytes(plainText)
                # ...except for the last one, that is padded
                if endIndex == fileSize:
                    # get the lenght of padding
                    a = decBlock[7]
                    # remove the extra bytes and write the remaining data
                    while a > 0:
                        decBlock.pop()
                        a -= 1
                # write into output file
                fileOutput.write(bytearray(decBlock))
        fileOutput.flush()
        fileOutput.close()
        fileInput.close()


    # 32-bits left rotation function
    def Rol(self, x, r):
        tmp = (x >> (self.WORD_SIZE_N - r)) & 0x00000000ffffffff
        return (((x << r) | tmp) & 0x00000000ffffffff)
    
    
    # 32-bits right rotation function
    def Ror(self, x, r):
       tmp = (x << (self.WORD_SIZE_N - r)) & 0x00000000ffffffff
       return (((x >> r) | tmp) & 0x00000000ffffffff)
    

    # initialization vector: returns a 32-bits integer
    def IV(self):
        return secrets.randbits(32)

    
    # convert blocks of 4 bytes into 32-bits words using little-endian order:
    # first byte into the right-most 8-bits, and so on up to the left
    def bytesToWord32(self, inBytes):
        lenght = len(inBytes)
        outWords = [0] * (lenght // 4)
        j = 0
        for i in range(0, lenght, 4):
            outWords[j] = inBytes[i] | (inBytes[i + 1] << 8) | (inBytes[i + 2] << 16) | (inBytes[i + 3] << 24)
            j += 1
        return outWords
    

    # revert a 32-bits word into 4 bytes using little-endian order:
    # right-most 8-bits into the first byte, and so on up to the left
    def word32ToBytes(self, inWords):
        lenght = len(inWords)
        outBytes = [0] * (lenght * 4)
        j = 0
        for i in range(0, lenght):
            outBytes[j] = inWords[i] & 0xff
            outBytes[j + 1] = (inWords[i] >> 8) & 0xff
            outBytes[j + 2] = (inWords[i] >> 16) & 0xff
            outBytes[j + 3] = (inWords[i] >> 24) & 0xff
            j += 4
        return outBytes
    
    # key scheduler: gets a key and prepare a round key buffer
    def keySchedule(self, key):
        subKey = [0] * self.ROUNDS
        key = key
        A, B, C, D = key[0], key[1], key[2], key[3]

        for i in range(0, self.ROUNDS, 3):
            subKey[i] = A
            B = self.Ror(B, 8)
            B = (B + A) & 0x00000000ffffffff
            B ^= i
            A = self.Rol(A, 3)
            A ^= B

            subKey[i + 1] = A
            C = self.Ror(C, 8)
            C = (C + A) & 0x00000000ffffffff
            C ^= (i + 1)
            A = self.Rol(A, 3)
            A ^= C

            subKey[i + 2] = A
            D = self.Ror(D, 8)
            D = (D + A) & 0x00000000ffffffff
            D ^= (i + 2)
            A = self.Rol(A, 3)
            A ^= D
        return subKey


    # encrypt a block using the round key and the IV, and returns a crypted block
    def encrypt(self, plainText, roundKey, intVect):
        cipherText = plainText #[0, 0]
        plainText = plainText
        for i in range(0, self.ROUNDS):
            intVect[1] = self.Ror(intVect[1], 8)
            intVect[1] = (intVect[1] + intVect[0]) & 0x00000000ffffffff
            intVect[1] ^= roundKey[i]
            intVect[0] = self.Rol(intVect[0], 3)
            intVect[0] ^= intVect[1]
        cipherText[0] = plainText[0] ^ intVect[0]
        cipherText[1] = plainText[1] ^ intVect[1]
        return cipherText
  

    # decrypt a block using the round key and the IV, and returns a decrypted block
    def decrypt(self, cipherText, roundKey, intVect):
        plainText = cipherText #[0, 0]
        cipherText = cipherText
        for i in range(0, self.ROUNDS):
            intVect[1] = self.Ror(intVect[1], 8)
            intVect[1] = (intVect[1] + intVect[0]) & 0x00000000ffffffff
            intVect[1] ^= roundKey[i]
            intVect[0] = self.Rol(intVect[0], 3)
            intVect[0] ^= intVect[1]
        plainText[0] = cipherText[0] ^ intVect[0]
        plainText[1] = cipherText[1] ^ intVect[1]
        return plainText
  

    # string padding
    def padding(self, txt, lng, pad = 0, truncate = False):
        text = str(txt)
        # if it's a byte array, remove un-necessary chars
        if text.find("b'") != -1:
            text = text[2:-1]
        pad = pad
        # is truncate required?
        if truncate:
            if len(text) % lng == 0:
                # lenght is equal: return the given string
                return text
            else:
                # return padded string
                return text.ljust(len(text) + lng - (len(text) % lng))
        # check if the string is already padded mod lng
        if len(text) == lng:
            # return passed string
            return text
        elif len(text) > lng:
            return text[:lng]
        else:
            # return padded string
            return text.ljust(len(text) + lng - (len(text) % lng), chr(pad))