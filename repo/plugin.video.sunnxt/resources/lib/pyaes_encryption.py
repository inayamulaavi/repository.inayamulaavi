#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from base64 import b64encode, b64decode
import pyaes


class AESCipher:
    def __init__(self, key='A3s68aORSgHs$71P', iv=b'\x00' * 16):
        self.key = key.encode('utf-8')
        self.iv = iv

    def encrypt(self, data):
        encrypter = pyaes.Encrypter(pyaes.AESModeOfOperationCBC(self.key,
                                                                self.iv))
        ciphertext = encrypter.feed(data)
        ciphertext += encrypter.feed()
        ciphertext = b64encode(ciphertext)
        return ciphertext

    def decrypt(self, data):
        decrypter = pyaes.Decrypter(pyaes.AESModeOfOperationCBC(self.key,
                                                                self.iv))
        decrypted = decrypter.feed(b64decode(data))
        decrypted += decrypter.feed()
        return decrypted


if __name__ == '__main__':

    msg = '{"userid":"username@domain.com","password":"password"}'

    print('TESTING ENCRYPTION')
    aes = AESCipher()
    encrypted = aes.encrypt(msg)
    print('Ciphertext:\n', encrypted)

    print('\nTESTING DECRYPTION')
    print('Message...:', aes.decrypt(encrypted))
