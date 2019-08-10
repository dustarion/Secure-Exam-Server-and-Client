# Exam Server
# This server should only be started by the Exam Repo Admin
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

# Import Common Utility Files
sys.path.append(os.path.abspath("../Common"))
from examUtil import Payload, Con_header, Resp_header, Repolist, Exam_Helper
from HonConnection import sendMsg, recvMsg, recvall, SendWithAes, RecieveWithAES

# Import Crypto Utility Files
from HonSecure import GenerateRandomKey, GenerateRSAKeys, ReadRSAKeysFromDisk, ReadRSAPublicKeyFromDisk, EncryptWithRSA, DecryptWithRSA, GenerateAESKey, EncryptWithAES, DecryptWithAES

# Import Server Utility Files
sys.path.append(os.path.abspath("/ServerUtils"))


HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

# Temporary Cryptography Protocols
ServerKeyFolder = 'ServerData/ServerKeys'
ClientPublicKeyFolder = 'ServerData/PublicKeys/Client1'


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    print ('Exam Server Started!')
    s.bind((HOST, PORT))
    s.listen(5) # Up to 5 Clients
    print ('Waiting for clients...')

    # Server Setup
    ServerShouldRun = True
    ClientList = []

    while ServerShouldRun: # Run the server continuously
        conn, addr = s.accept() # Accept Connection from Client
        with conn:
            print('Connected by Client', addr)
            
            data = recvMsg(conn)
            if not data:
                print('Recieved ')
                break

            # Recieve a session key which is decrypted using server private key.
            ServerKey = ReadRSAKeysFromDisk(ServerKeyFolder)
            EncryptedSessionKey = data
            SessionKey = DecryptWithRSA(ServerKey[0], EncryptedSessionKey)

            # Use Session Key to Descrypt and Encrypt from this point onwards.

            # Request Client Identity
            SendWithAes(conn, SessionKey, 'RequestClientIdentity')



            # Receive Client Identity, Compare UserID and Password Hash with server database.
            # Send Server Repo Owner ID, Password Hash, Random Challenge String

            # Decrypt challenge string with clients public key, verify the challenge string matches.

            # Secure Connection Established




    
    s.close