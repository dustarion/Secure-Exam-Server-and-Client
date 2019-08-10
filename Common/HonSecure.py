# HonSecure
# This class implements an abstraction of most of the crypto functions used in the exam server.

# Import Crypto
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random

# Import Others
import ast
import base64
import hashlib
import binascii

"""
General Cryptographic Functions
"""
def GenerateRandomKey(keyByteLength):
    print('Generating random key of length ' + str(keyByteLength) + ' bytes')
    key = Crypto.Random.get_random_bytes(keyByteLength)
    return key

"""
RSA Cryptographic Function
"""
# Returns a randomly generated rsa key.
def GenerateRSAKeys():
    random_generator = Random.new().read
    # Generate public and private key
    key = RSA.generate(1024, random_generator)
    publickey = key.publickey()
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


# Returns the keys saved to disk given the folder of the keys.
def ReadRSAKeysFromDisk(keyFolder):
    privateKeyFile = keyFolder + "/private.pem"
    publicKeyFile = keyFolder + "/public.pem"

    # Private Key
    privHandle = open(privateKeyFile, 'rb')
    key = RSA.importKey(privHandle.read())
    print (key.exportKey())
    privHandle.close()

    # Public Key
    pubHandle = open(publicKeyFile, 'rb')
    publicKey = RSA.importKey(pubHandle.read())
    print (publicKey.exportKey())
    pubHandle.close()

"""
AES Cryptographic Function
We use AES256 for all AES related operations.

def SampleAESImplementation():
    key = GenerateAESKey()
    data = str.encode('Hello World!')
    EData = EncryptWithAES(key, data)
    iv = EData[0]
    print(DecryptWithAES(key, iv, EData[1]))
"""
# AES Settings
AESKeyBytes = 32

# Generate a random 32 byte key.
def GenerateAESKey():
    # 256 Bit Keys
    return GenerateRandomKey(32)

# # Generate a random 16 byte initialisation vector.
# def GenerateIV():
#     # 128 Bit Blocks
#     return GenerateRandomKey(16)

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