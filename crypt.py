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

def Encrypt(key:str, text:str):
    if len(key) < 32: key += ' ' * (32 - len(key))
    elif len(key) > 32: key = key[0:32]
    btxt = base64.b64encode(text.encode('utf-8'))
    if len(btxt) < 32: btxt += b' ' * (32 - len(btxt))
    elif len(btxt) > 32: btxt = btxt[0:32]
    cipher = AES.new(bytes(key,encoding='utf-8'), AES.MODE_CBC, bytes(AES.block_size))
    print(btxt)
    return gzip.compress(bytes.strip(cipher.encrypt(btxt)))

def Decrypt(key:str, text:str) -> str:
    if len(key) < 32:
        key += ' ' * (32 - len(key))
    elif len(key) > 32:
        key = key[0:32]
    cipher = AES.new(bytes(key,encoding='utf-8'), AES.MODE_CBC, bytes(AES.block_size))
    return str(gzip.decompress(bytes.strip(cipher.decrypt(base64.b64decode(text)))), encoding='utf-8')

cipher_text = Encrypt("123","hulkcao")

#print('encrypt:'+cipher_text)

#ret = Decrypt("123",cipher_text)
#print("ret:",ret)