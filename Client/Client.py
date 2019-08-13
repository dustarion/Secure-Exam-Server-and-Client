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
from examUtil import ExamHelper, Payload
#Con_header, Resp_header, Repolist, Exam_Helper
from HonConnection import sendMsg, recvMsg, recvall, SendWithAES, RecieveWithAES, SendTupleWithAES, RecieveTupleWithAES

# Import Crypto Utility Files
from HonSecure import GenerateRandomKey, GenerateRandomSalt, GenerateHash, VerifyHash, GenerateHashWithSalt, VerifyHashWithSalt, GenerateSaltedHash, GenerateRSAKeys, ReadRSAKeysFromDisk, ReadRSAPublicKeyFromDisk, EncryptWithRSA, DecryptWithRSA, GenerateAESKey, EncryptWithAES, DecryptWithAES

# Import Client Utility Files
sys.path.append(os.path.abspath("../Client/ClientUtils"))
from ClientUtils import CheckUserExist, GetUserData, CheckUserRole, CheckRepoOwner, LoginUser, GetUserPasswordHash, EstablishSecureClientConnection

# Declare
MetaFolder = 'ClientData/'
HostMetaLocation = MetaFolder + 'ClientMETA.info'
ServerKeyFolder = 'ClientData/ServerKeys'
ClientPublicKeyFolder = 'ClientData/PublicKeys/'

# Initialise
ServerIP = '127.0.0.1'
PortNumber = 99999
ClientID = ''
RepoOwnerID = ''
PrincipalAdminID = ''
BackupAdminIDs = []
PasswordHash    = ''

# HOST = '127.0.0.1'  # The server's hostname or IP address
# PORT = 65432        # The port used by the server

# Temporary Cryptography Protocols
ClientKeyFolder = 'ClientData/ClientKeys'
ServerPublicKeyFolder = 'ClientData/PublicKeys/Server'

# Server Welcome Message
def ClientWelcomeMessage():
    print ('\nWelcome To Exam Client.')
    print ('Starting Exam Client...\n')

#  Reads a given META file and returns a list.
def ReadMeta(metaFileLocation):
    # Check if the given META file exists.
    exists = os.path.isfile(metaFileLocation)
    if exists:
        # Load in the Pre-Definied META Information
        try:
            # Load each line of the META file into a list.
            tmp_list=[]
            with open (metaFileLocation) as meta:
                for line in meta:
                    tmp_list.append(line.strip())
                meta.close()
            
            # Attempt to Check if Meta file is of a valid format.
            if len(tmp_list) < 1:
                print("Corrupted Meta file, please initialize again")
                sys.exit(-1)

            return tmp_list

        except:
            print("Corrupted Meta file, please initialize again.\nTerminating...")
            sys.exit(-1)


    else:
        # META file does not exist, terminate program.
        print(metaFileLocation)
        print('META File Is Missing\nTerminating...')
        exit(-1)

# Load the Host Meta File
def LoadMeta():
    # Host Meta
    print(HostMetaLocation)
    tmp_list = ReadMeta(HostMetaLocation)
    """
    Format of Server Meta:
    [IP Number]
    [Port Number]
    [Staff ID]
    [Repo Owner ID]
    [Principal Admin ID]
    [Backup Admin IDs...]
    """
    if (len(tmp_list) < 3):
        print("Corrupted Host_Meta file, please initialize again")
        sys.exit(-1)

    global ServerIP
    global PortNumber
    global ClientID
    global RepoOwnerID
    global PrincipalAdminID

    ServerIP         = tmp_list[0]
    PortNumber       = tmp_list[1]
    ClientID         = tmp_list[2]
    RepoOwnerID      = tmp_list[3]
    PrincipalAdminID = tmp_list[4]

    if (len(tmp_list) > 5):
        for baID in range(4, (len(tmp_list)-1)):
            if tmp_list[baID] != None and len(tmp_list[baID].strip())>0:
                BackupAdminIDs.append(tmp_list[baID])

def UserAuthenticate(UserID):
    return CheckUserExist(UserID)

def PasswordAuthenticate(UserID, Password):
    global PasswordHash
    response = LoginUser(UserID, Password)
    if response[0]:
        # Set Password Hash
        PasswordHash = response[1]
    return response

def UserSetup():

    # Instructions
    print("\nExam Client Startup Configuration")

    # Define Globals
    global ServerIP
    global PortNumber
    global ClientID
    global RepoOwnerID
    global PrincipalAdminID

    # Server IP
    ServerIP = ExamHelper.MyInput("Server IP address =>", ServerIP)
    if (ServerIP == None) or (len(ServerIP) == 0):
        print("Invalid Server IP\nTerminating...")
        exit(-1)

    # Server Port Number
    PortNumber = ExamHelper.MyInput("Server Port No. (9000-20000) =>", PortNumber)
    if (PortNumber == None) or (len(PortNumber) == 0):
        print("Invalid Port Number\nTerminating...")
        exit(-1)
    try:
        PortNumber=int(PortNumber)
        if not  PortNumber in range (9000,20001):
            print("Port Number Out Of Valid Range\nTerminating...")
            exit(-1)

    except:
        print("Invalid Port Number\nTerminating...")
        exit(-1)
    
    # Repo Owner ID
    RepoOwnerID = ExamHelper.MyInput("Repo owner ID =>", RepoOwnerID)
    if (RepoOwnerID == None) or (len(RepoOwnerID) == 0):
        print("Invalid Repo Owner ID\nTerminating...")
        exit(-1)
    
    # Staff ID
    ClientID = ExamHelper.MyInput("Staff ID =>", ClientID)
    if (ClientID == None) or (len(ClientID) == 0):
        print("Invalid Staff ID\nTerminating...")
        exit(-1)

    # Check that Repo Owner ID is confirmed
    if not UserAuthenticate(ClientID):
        print("Staff ID Authentication Failed.\nTerminating...")
        sys.exit(-1)

    # Verify Repo Owner Password
    print("Staff ID Authentication Passed. Please login.")
    password = getpass.getpass()
    password = 'passwordClient'
    if not PasswordAuthenticate(ClientID, password):
        print("Password Authentication Failed.\nTerminating...")
        sys.exit(-1)
    
    # Everything is Confirmed.
    # Update the Host_META.info
    with open(HostMetaLocation,'w') as meta:
        print(ServerIP,file=meta)
        print(PortNumber,file=meta)
        print(ClientID,file=meta)
        print(RepoOwnerID,file=meta)
        print(PrincipalAdminID,file=meta)
        for bAdmin in BackupAdminIDs:
            print(bAdmin,file=meta)
        meta.close()
# End UserSetup()
def List():
    print('You Chose List')

def Upload():
    print('You Chose Upload')

def Download():
    print('You Chose Download')

def UserChoice():
    # User has three options, Upload, Download, List
    print("\nType the approriate letter to continue.")
    print("L - List all exams.")
    print("U - Upload an exams.")
    print("D - Download an exams.")
    choice = input("Your Choice: ")

    if choice == 'L' or choice == 'l':
        print('You Chose List')
        List()
    elif choice == 'U' or choice == 'u':
        print('You Chose Upload')
        Upload()
    elif choice == 'D' or choice == 'd':
        print('You Chose Download')
        Download()
    else:
        print('\nInvalid Letter, try again.')
        UserChoice() # Recursive Loop until a valid letter is entered.

# Client
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    # Setup
    ClientWelcomeMessage()
    LoadMeta()
    UserSetup()

    # Client Start
    try:
        s.connect((ServerIP, PortNumber))

        # Establish Secure Connection and Obtain Session Key
        SessionKey = EstablishSecureClientConnection(RepoOwnerID, ClientID, PasswordHash, s, ClientKeyFolder, ServerPublicKeyFolder)

        # Ask the user what they want to do.
        #UserChoice()

    except ConnectionRefusedError:
        print('\nUnable to Connect To Server.\nEnsure the server is on.\nTerminating...')
        exit(-1)