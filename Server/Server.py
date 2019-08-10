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

# Import Crypto Utility Files
from HonSecure import GenerateRandomKey, GenerateRSAKeys, ReadRSAKeysFromDisk, ReadRSAPublicKeyFromDisk, EncryptWithRSA, DecryptWithRSA, GenerateAESKey, EncryptWithAES, DecryptWithAES

# Import Server Utility Files
sys.path.append(os.path.abspath("/ServerUtils"))


HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

# Temporary Cryptography Protocols
ServerKeyFolder = 'ServerData/ServerKeys'
ClientPublicKeyFolder = 'ServerData/PublicKeys/Client1'

# Connection Protocol
def sendMsg(sock, msg):
    # Prefix each message with a 4-byte length (network byte order)
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)

def recvMsg(sock):
    # Read message length and unpack it into an integer
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    # Read the message data
    return recvall(sock, msglen)

def recvall(sock, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data



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
            EncryptedSessionKey = int(data.decode("utf-8"))
            SessionKey = DecryptWithRSA(ServerKey[0], EncryptedSessionKey)
            print(SessionKey)

            # Use Session Key to Descrypt and Encrypt from this point onwards.

            # Request Client Identity

            # Receive Client Identity, Compare UserID and Password Hash with server database.
            # Send Server Repo Owner ID, Password Hash, Random Challenge String

            # Decrypt challenge string with clients public key, verify the challenge string matches.

            # Secure Connection Established




    
    s.close