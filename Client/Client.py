# Exam Client
# This server should only be started by the Examiner or Repo Admin
# Author: Dalton Prescott
# Date: August 2019
# Ver. 1.0


# Import Files
import sys, traceback
import os , re, time
import socket, ssl
import socketserver
import pickle
import struct
import getpass

# Import Common Utility Files
sys.path.append(os.path.abspath("../Common"))
from examUtil import Payload, Con_header, Resp_header, Repolist, Exam_Helper
from HonConnection import sendMsg, recvMsg, recvall, SendWithAES, RecieveWithAES, SendTupleWithAES, RecieveTupleWithAES

# Import Crypto Utility Files
from HonSecure import GenerateRandomKey, GenerateRandomSalt, GenerateHash, VerifyHash, GenerateHashWithSalt, VerifyHashWithSalt, GenerateSaltedHash, GenerateRSAKeys, ReadRSAKeysFromDisk, ReadRSAPublicKeyFromDisk, EncryptWithRSA, DecryptWithRSA, GenerateAESKey, EncryptWithAES, DecryptWithAES

# Import Client Utility Files
sys.path.append(os.path.abspath("/ClientUtils"))

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

# Temporary Cryptography Protocols
ClientKeyFolder = 'ClientData/ClientKeys'
ServerPublicKeyFolder = 'ClientData/PublicKeys/Server'


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    #try:
    s.connect((HOST, PORT))
    # while True:
        # s.sendall(b'Hello, world')
        # data = s.recv(1024)
        # print('Received', repr(data))

    # Generate Session Key
    SessionKey = GenerateAESKey()

    # Encrypt Session Key with Public Key of Server
    ServerPublicKey = ReadRSAPublicKeyFromDisk(ServerPublicKeyFolder)
    Payload = EncryptWithRSA(ServerPublicKey, SessionKey) #bytes(, encoding='utf8')

    sendMsg(s, Payload)

    # Use Session Key to Descrypt and Encrypt from this point onwards.

    # Recieve request for client identity
    request = RecieveWithAES(s, SessionKey)
    if request != b'RequestClientIdentity':
        print('Recieved Unknown Request\nTerminating...')
        exit()
    
    # Send Clients UserID and Password Hash
    salt = 'KE9C2mx6225XcC5isRIa/g=='
    userID = '2'
    password = 'passwordClient' 
    print('\n[Login]\nNote that your password will not show when you type for security reasons.\n')
    #userID = input('Enter your UserID: ')
    #password = getpass.getpass()

    clientIdentity = (userID, GenerateHashWithSalt(pickle.dumps(password), pickle.dumps(salt)))
    SendTupleWithAES(s, SessionKey, clientIdentity)

    # Recieve Repo Owner ID and Password Hash (Also a random challenge string)
    # Compare with Local Database
    ServerPasswordHash = '71eb1246bc9baeef38afe9b3f58291c9300bcfc8eb781997a7b1eadf79b4d641' 


    # Encrypt Challenge String with Private Key.

    # Recieve successful response.

    # Secure Connection Established
    



    #catch:

#print('Received', repr(data))