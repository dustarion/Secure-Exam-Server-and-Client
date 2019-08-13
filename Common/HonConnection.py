# HonConnection
# This class implements an abstraction of most of the crypto functions used in the exam server.

# Import Files
import sys, traceback
import os , re, time
import socket, ssl
import socketserver
import pickle
import struct

# Import Common Utility Files
#from examUtil import Payload, Con_header, Resp_header, Repolist, Exam_Helper

# Import Crypto Utility Files
from HonSecure import GenerateRandomKey, GenerateRandomSalt, GenerateHash, VerifyHash, GenerateHashWithSalt, VerifyHashWithSalt, GenerateSaltedHash, GenerateRSAKeys, ReadRSAKeysFromDisk, ReadRSAPublicKeyFromDisk, EncryptWithRSA, DecryptWithRSA, GenerateAESKey, EncryptWithAES, DecryptWithAES

# General Connection Protocol
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

# Cryptographic Connections
def SendWithAES(socket, key, unecryptedPayload):
    encryptedMsg = EncryptWithAES(key, unecryptedPayload)
    # encryptedMsg is a tuple -> (iv, cipherdata)
    temp = (encryptedMsg[0], encryptedMsg[1])
    hash = GenerateHash(pickle.dumps(temp).strip())
    msg = (temp, hash)

    # Send request to client
    Payload = pickle.dumps(msg)
    sendMsg(socket, Payload)

def RecieveWithAES(socket, key):
    data = recvMsg(socket)
    if not data:
        print('Recieved ')
        return ''
    RecievedPayload = pickle.loads(data)
    temp = RecievedPayload[0]
    hash = RecievedPayload[1]

    if VerifyHash(hash, pickle.dumps(temp).strip()):
        # Hash Matches
        iv = temp[0]
        msg = DecryptWithAES(key, iv, temp[1])
        return msg
    else:
        print('Message Integrity Check Failed\nTerminating...')
        exit()

def SendTupleWithAES(socket, key, unecryptedPayload):
    unecryptedPayload = pickle.dumps(unecryptedPayload)
    SendWithAES(socket, key, unecryptedPayload)

def RecieveTupleWithAES(socket, key):
    return pickle.loads(RecieveWithAES(socket, key))