# HonSecure
# This class implements an abstraction of most of the crypto functions used in the exam server.

# Import Crypto
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256

# Import Others
import os
import ast
import base64
import hashlib
import binascii
import pickle

"""
General Cryptographic Functions
"""
def GenerateRandomKey(keyByteLength):
    key = get_random_bytes(keyByteLength)
    return key

def GenerateRandomSalt(length):
    salt = base64.b64encode(os.urandom(length))
    return salt

"""
SHA256 Hashing Cryptographic Functions
# print ('passwordClient')
# print (GenerateSaltedHash(b'passwordClient'))

# print ('passwordServer')
# print (GenerateSaltedHash(b'passwordServer'))
"""

# Data must be a byte string or byte array.
def GenerateHash(payload):
    hashObj = SHA256.new(data=payload)
    return hashObj.hexdigest()

# Hash in hexdigest format
def VerifyHash(hash, payload):
    hashObj = SHA256.new(data=payload)
    return hashObj.hexdigest() == hash

def GenerateHashWithSalt(payload, salt):
    hashObj = SHA256.new(data=payload)
    hashObj.update(salt)
    return (hashObj.hexdigest())

# Hash in hexdigest format
def VerifyHashWithSalt(hash, payload, salt):
    hashObj = SHA256.new(data=payload)
    hashObj.update(salt)
    return hashObj.hexdigest() == hash

def GenerateSaltedHash(payload):
    salt = GenerateRandomSalt(16)
    return (GenerateHashWithSalt(payload, salt), salt)

def GenerateHashForPassword(password):
    salt = GenerateRandomSalt(16)
    return (GenerateHashWithSalt(pickle.dumps(password), pickle.dumps(salt)), salt)

# print (GenerateHashForPassword('passwordServer'))

"""
RSA Cryptographic Functions
"""
# Returns a randomly generated rsa key.
def GenerateRSAKeys():
    # Generate public and private key
    key = RSA.generate(2048)
    print('Successfully generated RSA key.')
    return (key)


# Saves the given key to disk.
def SaveRSAKeysToDisk(key, keyFolder):
    privateKeyFile = keyFolder + "/private.pem"
    publicKeyFile = keyFolder + "/public.pem"

    # Private Key
    privHandle = open(privateKeyFile, 'wb')
    privHandle.write(key.exportKey())
    privHandle.close()

    # Public Key
    pubHandle = open(publicKeyFile, 'wb')
    pubHandle.write(key.publickey().exportKey())
    pubHandle.close()

# SaveRSAKeysToDisk(GenerateRSAKeys(), 'Output')


# Returns the keys saved to disk given the folder of the keys.
def ReadRSAKeysFromDisk(keyFolder):
    privateKeyFile = keyFolder + "/private.pem"
    publicKeyFile = keyFolder + "/public.pem"

    # Private Key
    privHandle = open(privateKeyFile, 'rb').read()
    key = RSA.importKey(privHandle)

    # Public Key
    pubHandle = open(publicKeyFile, 'rb').read()
    publicKey = RSA.importKey(pubHandle)

    return (key, publicKey)

def ReadRSAPublicKeyFromDisk(keyFolder):
    publicKeyFile = keyFolder + "/public.pem"

    # Public Key
    pubHandle = open(publicKeyFile, 'rb').read()
    publicKey = RSA.importKey(pubHandle)

    return publicKey

def EncryptWithRSA(publicKey, sessionKey):
    cipherRSA = PKCS1_OAEP.new(publicKey)
    encryptedSessionKey = cipherRSA.encrypt(sessionKey)
    return encryptedSessionKey

def  DecryptWithRSA(key, encryptedSessionKey):
    cipherRSA = PKCS1_OAEP.new(key)
    sessionKey = cipherRSA.decrypt(encryptedSessionKey)
    return sessionKey


"""
AES Cryptographic Functions
We use AES256 for all AES related operations.
"""

# AES Settings
AESKeyBytes = 32

# Generate a random 32 byte key.
def GenerateAESKey():
    # 256 Bit Keys
    return GenerateRandomKey(32)

# Takes as input a 32-byte key and an arbitrary-length data.
# Returns a pair (iv, ciphterdata). "iv" stands for initialization vector.
def EncryptWithAES(key, data):
    assert len(key) == AESKeyBytes

    # Choose a random, 16-byte IV.
    iv = Random.new().read(AES.block_size)

    # Convert the IV to a Python integer.
    iv_int = int(binascii.hexlify(iv), 16)

    # Create a new Counter object with IV = iv_int.
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)

    # Create AES-CTR cipher.
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    # Encrypt and return IV and ciphertext.
    cipherdata = aes.encrypt(data)
    return (iv, cipherdata)

def DecryptWithAES(key, iv, cipherdata):
    assert len(key) == AESKeyBytes

    # Initialize counter for decryption. iv should be the same as the output of encrypt().
    iv_int = int(binascii.hexlify(iv), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)

    # Create AES-CTR cipher.
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    # Decrypt and return the plaintext.
    data = aes.decrypt(cipherdata)
    return data