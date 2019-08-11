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

class Exam_client:

    # Temporary Network Configuration
    # Read META file to obtain Network Configuration
    HOST, PORT = "localhost", 9999

    # A class method to display the program usage
    def usage(argv):
        print(f"Usage: {argv[0]} "+" {-i | -L | -u | -r | -f}")
        print("required optins:")
        print("-i : META INFO initalization at current directory")
        print("-L : List all payloads")
        print("-u : upload examination payload from upload directory")
        print("-r : retrive examintion payload and save in download directory")

    # Class Initialisation
    # Load the Meta File
    def __init__(self):
        self.block_size = 1024
        self.timeout_in_seconds = Exam_Helper.timeout_in_seconds  # default socket timeout 
        self.my_input = Exam_Helper.my_input # link to external helper function
        self.repo_owner_id = "" # SOC Exam Repo Owner id
        self.server_ip, self.server_port = "localhost", "9999" # initialize with default value
        self.staff_id, self.mod_code, self.exam_fn, self.sol_fn = "","","",""
        #The first task is to check if META file exist
        #if not, must prompt for the META info.
        exists = os.path.isfile('META.info')
        if not exists:
            self.init_meta()
        else:
            # load in pre-defined meta info
            try:
                with open('META.info') as meta:
                    self.server_ip=meta.readline().strip()
                    self.server_port=meta.readline().strip()
                    self.repo_owner_id=meta.readline().strip()
                    self.repo_owner_password_hash=meta.readline().strip()
                    self.staff_id=meta.readline().strip()
                    self.mod_code=meta.readline().strip()
                    if self.mod_code != None and len(self.mod_code) > 0:
                        self.exam_fn=meta.readline().strip()
                        self.sol_fn=meta.readline().strip()
                    meta.close()
            except:
                print("Corrupted Meta file, please initialize again")
                sys.exit(-1)
    