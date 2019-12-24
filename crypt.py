#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
import base64
import time
import gzip
from hashlib import md5
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding='utf-8', line_buffering=True)

def Encrypt(key:str, text:str) -> str:
    if len(key) < 32: key += ' ' * (32 - len(key))
    elif len(key) > 32: key = key[0:32]
    cipher = AES.new(bytes(key,encoding='utf-8'), AES.MODE_CBC, bytes(AES.block_size))
    return str(gzip.decompress(bytes.strip(cipher.encrypt(base64.b64decode(text)))), encoding='utf-8')

cipher_text = Encrypt("123","aaaaaa")

print('encrypt:'+cipher_text)
'''
# Encryption
encryption_suite = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
cipher_text = encryption_suite.encrypt("A really secret message. Not for prying eyes.")

Encrypt('This is a key123')
# Decryption
decryption_suite = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
plain_text = decryption_suite.decrypt(cipher_text)
'''