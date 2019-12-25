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

def SimpleEncrypt(key:str,text:str)->str:
    if len(key) < 32: key += ' ' * (32 - len(key))
    elif len(key) > 32: key = key[0:32]
    if len(text) < 32: text += ' ' * (32 - len(text))
    elif len(text) > 32: text = text[0:32]
    cipher = AES.new(bytes(key,encoding='utf-8'), AES.MODE_CBC, bytes(AES.block_size))
    return str(base64.b64encode(cipher.encrypt(text)),encoding=('utf-8'))

def SimpleDecrypt(key,text):
    if len(key) < 32: key += ' ' * (32 - len(key))
    elif len(key) > 32: key = key[0:32]
    cipher = AES.new(bytes(key,encoding='utf-8'), AES.MODE_CBC, bytes(AES.block_size))
    return str(cipher.decrypt(base64.b64decode(text)),encoding=('utf-8'))

def Encrypt(key:str, text:str):
    if len(key) < 32: key += ' ' * (32 - len(key))
    elif len(key) > 32: key = key[0:32]
    if len(text) < 32: text += ' ' * (32 - len(text))
    elif len(text) > 32: text = text[0:32]
    cipher = AES.new(bytes(key,encoding='utf-8'), AES.MODE_CBC, bytes(AES.block_size))
    return str(base64.b64encode(gzip.compress(bytes.strip(cipher.encrypt(text)))),encoding=('utf-8'))

def Decrypt(key:str, text:str) -> str:
    if len(key) < 32: key += ' ' * (32 - len(key))
    elif len(key) > 32: key = key[0:32]
    cipher = AES.new(bytes(key,encoding='utf-8'), AES.MODE_CBC, bytes(AES.block_size))
    return str(gzip.decompress(bytes.strip(cipher.decrypt(base64.b64decode(text)))), encoding='utf-8')

cipher_text = SimpleEncrypt("123","haha")
print('simple encrypt:',cipher_text)
print('simple decrypt:',SimpleDecrypt("123",cipher_text))

if __name__ == "__main__":
    #key = input("1+2=")
    step_num = 3
    for step_i in range(step_num):
        msg = input("step:%s please input msg",step_num-step_i)
        answer = input("step:%s please input answer",step_num-step_i)
        if step_i == 0:
            crypt_text = SimpleEncrypt(answer,msg)
            key='''input('%s')exec(SimpleDecrypt(%s,%s))'''