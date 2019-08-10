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
    privHandle.close()

    # Public Key
    pubHandle = open(publicKeyFile, 'rb')
    publicKey = RSA.importKey(pubHandle.read())
    pubHandle.close()

    return (key, publicKey)

def ReadRSAPublicKeyFromDisk(keyFolder):
    publicKeyFile = keyFolder + "/public.pem"

    # Public Key
    pubHandle = open(publicKeyFile, 'rb')
    publicKey = RSA.importKey(pubHandle.read())
    pubHandle.close()

    return publicKey

def EncryptWithRSA(publickey, data):
    return publickey.encrypt(32, data)[0] # For some reason it's a tuple

def  DecryptWithRSA(key, encryptedData):
    return key.decrypt(ast.literal_eval(str(encryptedData))) # For some reason it's a tuple


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






# Sample Code Dump (Delete Later)
# def EncryptWithRSA(Str text):
#     encrypted = publickey.encrypt(32, 'encrypt this message')




#class HonSecure():
random_generator = Random.new().read
key = RSA.generate(1024, random_generator) #generate pub and priv key
publickey = key.publickey() # pub key export for exchange

encrypted = publickey.encrypt(32, 'encrypt this message')
# #message to encrypt is in the above line 'encrypt this message'

print ('encrypted message:', encrypted) #ciphertext
# f = open ('encryption.txt', 'w')
# f.write(str(encrypted)) #write ciphertext to file
# f.close()

# #decrypted code below

# f = open('encryption.txt', 'r')
# message = f.read()

decrypted = key.decrypt(ast.literal_eval(str(encrypted)))
print ('decrypted', decrypted)

# f = open ('encryption.txt', 'w')
# f.write(str(message))
# f.write(str(decrypted))
# f.close()


# data = "I met aliens in UFO. Here is the map.".encode("utf-8")
# file_out = open("encrypted_data.bin", "wb")

key = RSA.generate(2048)
session_key = get_random_bytes(16)
print(session_key)

recipient_key = key.publickey()

# Encrypt the session key with the public RSA key
cipher_rsa = PKCS1_OAEP.new(recipient_key)
enc_session_key = cipher_rsa.encrypt(session_key)

# Encrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data)
[ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]

private_key = key

# Decrypt the session key with the private RSA key
cipher_rsa = PKCS1_OAEP.new(private_key)
session_key2 = cipher_rsa.decrypt(enc_session_key)
print (session_key2)

# Decrypt the data with the AES session key
# cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
# data = cipher_aes.decrypt_and_verify(ciphertext, tag)
# print(data.decode("utf-8"))