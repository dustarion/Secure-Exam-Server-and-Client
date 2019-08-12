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
sys.path.append(os.path.abspath("../Server/ServerUtils"))
from ServerUtils import CheckUserExist, GetUserData, CheckUserRole, CheckRepoOwner, LoginUser, GetUserPasswordHash, EstablishSecureServerConnection


# Declare
MetaFolder = 'ServerData/'
HostMetaLocation = MetaFolder + 'HostMETA.info'
ServerKeyFolder = 'ServerData/ServerKeys'
ClientPublicKeyFolder = 'ServerData/PublicKeys/'

# Initialise
ServerIP       = '127.0.0.1'
PortNumber     = 99999
RepoOwnerID    = ''
PrincipalAdminID = ''
BackupAdminIDs = []

PasswordHash    = ''

# HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
# PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

# Server Welcome Message
def ServerWelcomeMessage():
    print ('\nWelcome To Exam Server.')
    print ('Starting Exam Server...\n')

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
                print("Corrupted Host_Meta file, please initialize again")
                sys.exit(-1)

            return tmp_list

        except:
            print("Corrupted Host_Meta file, please initialize again.\nTerminating...")
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
    [Port Number]
    [Repo Owner ID]
    [Primary Admin ID]
    [Backup Admin IDs...]
    """
    if (len(tmp_list) < 3):
        print("Corrupted Host_Meta file, please initialize again")
        sys.exit(-1)

    global PortNumber
    global RepoOwnerID
    global PrincipalAdminID

    PortNumber     = tmp_list[0]
    RepoOwnerID    = tmp_list[1]
    PrincipalAdminID = tmp_list[2]

    if (len(tmp_list) > 3):
        for baID in range(3, (len(tmp_list)-1)):
            if tmp_list[baID] != None and len(tmp_list[baID].strip())>0:
                BackupAdminIDs.append(tmp_list[baID])

def OwnerAuthenticate(RepoOwnerID):
    return CheckRepoOwner(RepoOwnerID)

def PasswordAuthenticate(RepoOwnerID, Password):
    global PasswordHash
    response = LoginUser(RepoOwnerID, Password)
    if response[0]:
        # Set Password Hash
        PasswordHash = response[1]
    return response

def UserSetup():

    # Instructions
    print("\nExam Server Startup Configuration")

    # Define Globals
    global PortNumber
    global RepoOwnerID
    global PrincipalAdminID

    # Server Port Number
    PortNumber = Exam_Helper.my_input("Server Port No. (9000-20000) =>", PortNumber)
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
    RepoOwnerID = Exam_Helper.my_input("Repo owner ID =>", RepoOwnerID)
    if (RepoOwnerID == None) or (len(RepoOwnerID) == 0):
        print("Invalid Repo Owner ID\nTerminating...")
        exit(-1)
    
    # Principal Exam Repo Administrator ID
    PrincipalAdminID = Exam_Helper.my_input("Principal Exam Repo Administrator ID =>", PrincipalAdminID)
    if (PrincipalAdminID == None) or (len(PrincipalAdminID) == 0):
        print("Invalid Principal Exam Repo Administrator ID\nTerminating...")
        exit(-1)

    # Check that Repo Owner ID is confirmed
    if not OwnerAuthenticate(RepoOwnerID):
        print("Exam Repo Owner Authentication Failed.\nTerminating...")
        sys.exit(-1)

    # Verify Repo Owner Password
    print("Exam Repo Owner Authentication Passed. Please login.")
    #password = getpass.getpass()
    password = 'passwordServer'
    if not PasswordAuthenticate(RepoOwnerID, password):
        print("Password Authentication Failed.\nTerminating...")
        sys.exit(-1)

    # Backup Administrator List
    print("Authentication Success.\nNow, Review and Update the Backup Administrator list.")
    newBackupAdminIDs = []
    if len(BackupAdminIDs) > 0:
        for bkup in BackupAdminIDs:
            newID=Exam_Helper.my_input(f"Backup Administrator ID {len(newBackupAdminIDs)+1} =>",bkup)
            if newID != None and len(newID.strip())>0:
                newBackupAdminIDs.append(newID.strip())
    while True:
        newID=Exam_Helper.my_input(f"Backup Administrator ID {len(newBackupAdminIDs)+1} =>","")
        if newID != None and len(newID.strip())>0:
            newBackupAdminIDs.append(newID.strip())
        else:
            break
    
    # Everything is Confirmed.
    # Update the Host_META.info
    with open(HostMetaLocation,'w') as meta:
        print(PortNumber,file=meta)
        print(RepoOwnerID,file=meta)
        print(PrincipalAdminID,file=meta)
        for bAdmin in BackupAdminIDs:
            print(bAdmin,file=meta)   
        meta.close()
# End UserSetup()

# Server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

    # Setup
    ServerWelcomeMessage()
    LoadMeta()
    UserSetup()

    # Server Start
    s.bind((ServerIP, PortNumber))
    s.listen(5) # Up to 5 Clients
    print ('Waiting for clients...')

    while True: # Run the server continuously
        conn, addr = s.accept() # Accept Connection from Client
        with conn:
            print('Connected by Client', addr)
            data = recvMsg(conn)
            if not data:
                print('Recieved Unknown Request\nTerminating...')
                exit(-1)
            
            # Establish A Secure Connection with the client
            SessionKey = EstablishSecureServerConnection(RepoOwnerID, PasswordHash, conn, ServerKeyFolder, ClientPublicKeyFolder, data)
    
    #############################################################
    s.close