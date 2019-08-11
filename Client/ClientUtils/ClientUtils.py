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
    salt = "KE9C2mx6225XcC5isRIa/g=="
    userID = '2'
    password = 'passwordClient' 
    print('\n[Login]\nNote that your password will not show when you type for security reasons.\n')
    #userID = input('Enter your UserID: ')
    #password = getpass.getpass()

    clientIdentity = (userID, GenerateHashWithSalt(pickle.dumps(password), pickle.dumps(salt)))

    return clientIdentity


# Client Secure Connection
def EstablishSecureClientConnection(socket, ClientKeyFolder, ServerPublicKeyFolder):
    # Generate Session Key
    SessionKey = GenerateAESKey()

    # Encrypt Session Key with Public Key of Server
    ServerPublicKey = ReadRSAPublicKeyFromDisk(ServerPublicKeyFolder)
    Payload = EncryptWithRSA(ServerPublicKey, SessionKey)

    sendMsg(socket, Payload)

    # Use Session Key to Descrypt and Encrypt from this point onwards.

    # Recieve request for client identity
    request = RecieveWithAES(socket, SessionKey)
    if request != b'RequestClientIdentity':
        print('Recieved Unknown Request\nTerminating...')
        exit(-1)
    
    # Send Clients UserID and Password Hash
    clientIdentity = Login()
    SendTupleWithAES(socket, SessionKey, clientIdentity)

    # Recieve Repo Owner ID and Password Hash (Also a random challenge string)
    # Compare with Local Database
    ServerPasswordHash = 'e541fc35f5a53d83b815042a21af51fba903c03321c61f7ca1d883f9bf52df63' 
    RecievedPayload = RecieveTupleWithAES(socket, SessionKey)
    EncryptedChallengeString = RecievedPayload[0]
    ServerIdentity = RecievedPayload[1]
    if (ServerIdentity) != ('1', ServerPasswordHash):
        print('Recieved Unknown Request\nTerminating...')
        exit(-1)
    
    # Encrypt Challenge String with Private Key.
    ClientKey = ReadRSAKeysFromDisk(ClientKeyFolder)
    ChallengeString = DecryptWithRSA(ClientKey[0], EncryptedChallengeString)

    # Send to Server
    SendWithAES(socket, SessionKey, ChallengeString)

    # Recieve successful response.
    response = RecieveWithAES(socket, SessionKey)
    if response != b'Success':
        print('Recieved Unknown Request\nTerminating...')
        exit(-1)

    # Secure Connection Established
    print('\nSecure Connection Established!\n')

    return (SessionKey)