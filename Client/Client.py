# Exam Client
# This server should only be started by the Examiner or Repo Admin
# Author: Dalton Prescott
# Date: August 2019
# Ver. 1.0


# Import Files
import sys, traceback
# sys.path.append("..")
import os , re, time
import socket, ssl
#import socketserver
#import pickle
# import utility file!

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

# Temporary Cryptography Protocols
PrivateKey = 'asda'
PublicKey = 'dasd'
ServerPublicKey = ''

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    #try:
    s.connect((HOST, PORT))
    while True:
        s.sendall(b'Hello, world')
        data = s.recv(1024)
        print('Received', repr(data))

        # Generate Session Key

        # Encrypt Session Key with Public Key of Server

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