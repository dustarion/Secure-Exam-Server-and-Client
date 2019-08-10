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
import getpass

# Import Common Utility Files
sys.path.append(os.path.abspath("../Common"))
from examUtil import Payload, Con_header, Resp_header, Repolist, Exam_Helper
from HonConnection import sendMsg, recvMsg, recvall, SendWithAES, RecieveWithAES, SendTupleWithAES, RecieveTupleWithAES

# Import Crypto Utility Files
from HonSecure import GenerateRandomKey, GenerateRandomSalt, GenerateHash, VerifyHash, GenerateHashWithSalt, VerifyHashWithSalt, GenerateSaltedHash, GenerateRSAKeys, ReadRSAKeysFromDisk, ReadRSAPublicKeyFromDisk, EncryptWithRSA, DecryptWithRSA, GenerateAESKey, EncryptWithAES, DecryptWithAES

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
            SendWithAES(conn, SessionKey, 'RequestClientIdentity')

            # Receive Client Identity, Compare UserID and Password Hash with server database.
            ClientPasswordHash = '073f9dd9d134206828ea34f8d1c81b5150973fe7c470358f4e59528f8bc284a8'
            clientIdentity = RecieveTupleWithAES(conn, SessionKey)
            print(clientIdentity)
            if (clientIdentity) != ('2', ClientPasswordHash):
                print('Recieved Unknown Request\nTerminating...')
                exit()

            # Send Server Repo Owner ID, Password Hash, Random Challenge String
            salt = 'iOJDsoomr0YATKGwsaoN3A=='
            ownerID = '1'
            password = 'passwordServer' 
            print('\n[Login]\nNote that your password will not show when you type for security reasons.\n')
            #ownerID = input('Enter your OwnerID: ')
            #password = getpass.getpass()

            # Decrypt challenge string with clients public key, verify the challenge string matches.

            # Secure Connection Established




    
    s.close