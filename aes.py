from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Util import Counter
import sys
import getopt
import hashlib
import os
import binascii

#args, opts = getopt.getopt(sys.argv[1:], "f:m:")
#str = 'hello world'
#print([x for x in str])
#iv = hex(10)[2:8].zfill(16)
#str = 'novuen'
#iv =  ''.join(([ hex(int(ord(str[i])))[2:] for i in range(len(str))]))
#iv = iv.zfill(16).encode()

def encryptECB(plainText, key):
    plainText = pad(plainText, AES.block_size)
    key = key.encode().zfill(16)
    encryptor = AES.new(key, AES.MODE_ECB)
    return encryptor.encrypt(plainText)

def decryptECB(cipherText, key):
    #if str(type(cipherText))[8:-2] != 'bytes':
    #    cipherText = cipherText.encode()
    key = key.encode().zfill(16)
    decryptor = AES.new(key, AES.MODE_ECB)
    return unpad(decryptor.decrypt(cipherText), AES.block_size)

def encryptCBC(plaintext, key, iv):
    plaintext = pad(plaintext, AES.block_size)
    key = key.encode().zfill(16)
    iv = iv.encode().zfill(16)
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    return encryptor.encrypt(plaintext)

def decryptCBC(ciphertext, key, iv):
    key = key.encode().zfill(16)
    iv = iv.encode().zfill(16)
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    return unpad(decryptor.decrypt(ciphertext), AES.block_size)


def encryptCFB(plaintext, key, iv):
    plaintext = pad(plaintext, AES.block_size)
    key = key.encode().zfill(16)
    iv = iv.encode().zfill(16)
    encryptor = AES.new(key, AES.MODE_CFB, iv)
    return encryptor.encrypt(plaintext)

def decryptCFB(ciphertext, key, iv):
    key = key.encode().zfill(16)
    iv = iv.encode().zfill(16)
    decryptor = AES.new(key, AES.MODE_CFB, iv)
    return unpad(decryptor.decrypt(ciphertext), AES.block_size)


def encryptOFB(plaintext, key, iv):
    plaintext = pad(plaintext, AES.block_size)
    key = key.encode().zfill(16)
    iv = iv.encode().zfill(16)
    encryptor = AES.new(key, AES.MODE_OFB, iv)
    return encryptor.encrypt(plaintext)

def decryptOFB(ciphertext, key, iv):
    key = key.encode().zfill(16)
    iv = iv.encode().zfill(16)
    decryptor = AES.new(key, AES.MODE_OFB, iv)
    return unpad(decryptor.decrypt(ciphertext), AES.block_size)


def encryptCTR(plaintext, key):
    plaintext = pad(plaintext, AES.block_size)
    key = key.encode().zfill(16)
    ctr = Counter.new(128, initial_value=10)
    encryptor = AES.new(key, AES.MODE_CTR, counter=ctr)
    return encryptor.encrypt(plaintext)

def decryptCTR(ciphertext, key):
    key = key.encode().zfill(16)
    ctr = Counter.new(128, initial_value=10)
    decryptor = AES.new(key, AES.MODE_CTR, counter=ctr)
    return unpad(decryptor.decrypt(ciphertext), AES.block_size)




def readFile(filename):
    fileObj = open(filename, 'r+')
    data = fileObj.readlines()
    fileObj.close()
    return data

def writeFile(filename, data):
    fileObj = open(filename, 'w+')
    fileObj.writelines(data)
    fileObj.close()

def encryptFile(filename):
    data = readFile(filename)
    if data.__len__ == 0:
        print('file is empty!')
        return
    else:
        data = ''.join(data)
        encryptedData = binascii.hexlify(encryptECB(data.encode(), 'key')).decode()
        writeFile(filename, encryptedData)

def decryptFile(filename):
    data = readFile(filename)
    if data.__len__ == 0:
        print('file is empty')
        return
    else: 
        data = ''.join(data)
        decryptedData = decryptECB(binascii.unhexlify(data.encode()),'key').decode()
        writeFile(filename, ''.join(decryptedData))


x = binascii.hexlify('novuen'.encode())
y = int(x, 16)
print(x)
print(y)


