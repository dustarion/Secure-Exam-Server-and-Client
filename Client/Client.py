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
sys.path.append(os.path.abspath("../Client/ClientUtils"))
from ClientUtils import EstablishSecureClientConnection

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

# Temporary Cryptography Protocols
ClientKeyFolder = 'ClientData/ClientKeys'
ServerPublicKeyFolder = 'ClientData/PublicKeys/Server'

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    try:
        s.connect((HOST, PORT))

        # Establish Secure Connection and Obtain Session Key
        SessionKey = EstablishSecureClientConnection(s, ClientKeyFolder, ServerPublicKeyFolder)

    except ConnectionRefusedError:
        print('\nUnable to Connect To Server.\nEnsure the server is on.\nTerminating...')
        exit(-1)