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

# Import Common Utility Files
sys.path.append(os.path.abspath("../Common"))
from examUtil import Payload, Con_header, Resp_header, Repolist, Exam_Helper

# Import Crypto Utility Files
from HonSecure import GenerateRandomKey, GenerateRSAKeys, ReadRSAKeysFromDisk, ReadRSAPublicKeyFromDisk, EncryptWithRSA, DecryptWithRSA, GenerateAESKey, EncryptWithAES, DecryptWithAES

# Import Client Utility Files
sys.path.append(os.path.abspath("/ClientUtils"))

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

# Temporary Cryptography Protocols
ClientKeyFolder = 'ClientData/ClientKeys'
ServerPublicKeyFolder = 'ClientData/PublicKeys/Server'

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
    #try:
    #s.connect((HOST, PORT))
    # while True:
        # s.sendall(b'Hello, world')
        # data = s.recv(1024)
        # print('Received', repr(data))

    # Generate Session Key
    SessionKey = 'test' #str(GenerateAESKey())
    print(SessionKey)

    # Encrypt Session Key with Public Key of Server
    ServerPublicKey = ReadRSAPublicKeyFromDisk(ServerPublicKeyFolder)
    Payload = str(EncryptWithRSA(ServerPublicKey, SessionKey)) #bytes(, encoding='utf8')

    #sendMsg(s, Payload)

    ServerKey = ReadRSAKeysFromDisk('../Server/ServerData/ServerKeys')
    EncryptedSessionKey = int(Payload) #.decode("utf-8")
    SessionKey2 = DecryptWithRSA(ServerKey[0], EncryptedSessionKey)
    print (SessionKey2)

    # Use Session Key to Descrypt and Encrypt from this point onwards.

    # Recieve request for client identity
    # Send Clients UserID and Password Hash

    # Recieve Repo Owner ID and Password Hash (Also a random challenge string)
    # Compare with Local Database

    # Encrypt Challenge String with Private Key.

    # Recieve successful response.

    # Secure Connection Established




    #catch:

#print('Received', repr(data))