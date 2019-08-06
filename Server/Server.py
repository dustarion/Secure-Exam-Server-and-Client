# Exam Server
# This server should only be started by the Exam Repo Admin
# Author: Dalton Prescott
# Date: August 2019
# Ver. 1.0


# Import Files
import sys, traceback
import os , re, time
import socket, ssl
import thread
#import socketserver
#import pickle
# import utility file!
sys.path.append(os.path.abspath("../common"))
from examUtil import Payload, Con_header, Resp_header, Repolist, Exam_Helper

# Handle A New Client Connection
def on_new_client(clientsocket,addr):
    while True:
        msg = clientsocket.recv(1024)
        #do some checks and if msg == someWeirdSignal: break:
        print (addr, ' >> ', msg)
        msg = raw_input('SERVER >> ')
        #Maybe some code to compute the last digit of PI, play game or anything else can go here and when you are done.
        clientsocket.sendall(msg)
    clientsocket.close()



s = socket.socket()
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

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
        thread.start_new_thread(on_new_client,(c,addr))

    s.close




        # with conn:
        #     print('Connected by Client', addr)
        #     while True:
        #         data = conn.recv(1024)
        #         if not data:
        #             break
        #         conn.sendall(data)

























