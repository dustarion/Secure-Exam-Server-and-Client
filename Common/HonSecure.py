# HonSecure
# This class implements an abstraction of most of the crypto functions used in the exam server.

# Import Crypto
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random

# Import Others
import ast
import base64


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


def GenerateAESKey():
    print()


#-------------------------------------------------------------------------
# Test Code
SaveRSAKeysToDisk(GenerateRSAKeys(), 'Output')
ReadRSAKeysFromDisk('Output')





# def EncryptWithRSA(Str text):
#     encrypted = publickey.encrypt(32, 'encrypt this message')




#class HonSecure():
# random_generator = Random.new().read
# key = RSA.generate(1024, random_generator) #generate pub and priv key

# publickey = key.publickey() # pub key export for exchange

# encrypted = publickey.encrypt(32, 'encrypt this message')
# #message to encrypt is in the above line 'encrypt this message'

# print ('encrypted message:', encrypted) #ciphertext
# f = open ('encryption.txt', 'w')
# f.write(str(encrypted)) #write ciphertext to file
# f.close()

# #decrypted code below

# f = open('encryption.txt', 'r')
# message = f.read()


# decrypted = key.decrypt(ast.literal_eval(str(encrypted)))

# print ('decrypted', decrypted)

# f = open ('encryption.txt', 'w')
# f.write(str(message))
# f.write(str(decrypted))
# f.close()
    