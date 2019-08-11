# HonConnection
# This class implements an abstraction of most of the crypto functions used in the exam server.

# Import Files
import sys, traceback
import os , re, time
import socket, ssl
import socketserver
import pickle
import struct
import getpass

# Import Common Utility Files
sys.path.append(os.path.abspath("../../Common"))
from examUtil import Payload, Con_header, Resp_header, Repolist, Exam_Helper
from HonConnection import sendMsg, recvMsg, recvall, SendWithAES, RecieveWithAES, SendTupleWithAES, RecieveTupleWithAES

# Import Crypto Utility Files
from HonSecure import GenerateRandomKey, GenerateRandomSalt, GenerateHash, VerifyHash, GenerateHashWithSalt, VerifyHashWithSalt, GenerateSaltedHash, GenerateRSAKeys, ReadRSAKeysFromDisk, ReadRSAPublicKeyFromDisk, EncryptWithRSA, DecryptWithRSA, GenerateAESKey, EncryptWithAES, DecryptWithAES

# Login
def Login():
    salt = "b'qSIkoYy8uPzdAGET9/5aRA=='"
    ownerID = '1'
    password = 'passwordServer' 
    print('\n[Login]\nNote that your password will not show when you type for security reasons.\n')
    #ownerID = input('Enter your OwnerID: ')
    #password = getpass.getpass()

    serverIdentity = (ownerID, GenerateHashWithSalt(pickle.dumps(password), pickle.dumps(salt)))

    return serverIdentity


# Server Secure Connection
def EstablishSecureServerConnection(socket, ServerKeyFolder, ClientPublicKeyFolder, data):

    # Recieve a session key which is decrypted using server private key.
    ServerKey = ReadRSAKeysFromDisk(ServerKeyFolder)
    ClientPublicKey = ReadRSAPublicKeyFromDisk(ClientPublicKeyFolder)
    EncryptedSessionKey = data
    SessionKey = DecryptWithRSA(ServerKey[0], EncryptedSessionKey)

    # Use Session Key to Descrypt and Encrypt from this point onwards.

    # Request Client Identity
    SendWithAES(socket, SessionKey, 'RequestClientIdentity')

    # Receive Client Identity, Compare UserID and Password Hash with server database.
    ClientPasswordHash = '073f9dd9d134206828ea34f8d1c81b5150973fe7c470358f4e59528f8bc284a8'
    clientIdentity = RecieveTupleWithAES(socket, SessionKey)
    if (clientIdentity) != ('2', ClientPasswordHash):
        print('Recieved Unknown Request\nTerminating...')
        exit(-1)

    # Send Server Repo Owner ID, Password Hash, Random Challenge String
    serverIdentity = Login()

    # Challenge String
    challengeString = pickle.dumps(GenerateRandomSalt(16))
    encryptedChallengeString = EncryptWithRSA(ClientPublicKey, challengeString)

    payload = (encryptedChallengeString, serverIdentity)
    SendTupleWithAES(socket, SessionKey, payload)

    # Decrypt challenge string verify the challenge string matches.
    RecievedChallengeString = RecieveWithAES(socket, SessionKey)
    if challengeString != RecievedChallengeString:
        print('Recieved Unknown Request\nTerminating...')
        exit(-1)

    # Secure Connection Established
    SendWithAES(socket, SessionKey, b'Success')
    print('\nSecure Connection Established!\n')

    return (SessionKey)