# Exam Server
# This server should only be started by the Exam Repo Admin
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

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()

    ServerShouldRun = True

    while ServerShouldRun: # Run the server continuously
        conn, addr = s.accept() # Accept Connection from Client
        with conn:
            print('Connected by Client', addr)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                conn.sendall(data)

























