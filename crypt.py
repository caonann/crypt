#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
import base64
import time
import gzip
from hashlib import md5
import sys
import io
from binascii import b2a_hex, a2b_hex
sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding='utf-8', line_buffering=True)

def Encrypt(key:str, text:str) -> str:
    if len(key) < 32: key += ' ' * (32 - len(key))
    elif len(key) > 32: key = key[0:32]

    if len(text) < 32: text += ' ' * (32 - len(text))
    elif len(text) > 32: text = text[0:32]
    cipher = AES.new(bytes(key,encoding='utf-8'), AES.MODE_CBC, bytes(AES.block_size))
    return str(b2a_hex(gzip.compress(bytes.strip(cipher.encrypt(text)))), encoding='utf-8')

def Decrypt(key:str, text:str) -> str:
    if len(key) < 32:
        key += ' ' * (32 - len(key))
    elif len(key) > 32:
        key = key[0:32]

    btext = a2b_hex(text)
    cipher = AES.new(bytes(key,encoding='utf-8'), AES.MODE_CBC, bytes(AES.block_size))
    return str(gzip.decompress(bytes.strip(cipher.decrypt(btext))), encoding='utf-8')

cipher_text = Encrypt("123","aaaaaa")

print('encrypt:'+cipher_text)

ret = Decrypt("123",cipher_text)
print("ret:",ret)