# HonConnection
# This class implements an abstraction of most of the crypto functions used in the exam server.

# Import Files
import sys, traceback
import os , re, time
import socket, ssl
import socketserver
import pickle
import struct
import getpass

# Import Common Utility Files
sys.path.append(os.path.abspath("../../Common"))
from examUtil import Payload, Con_header, Resp_header, Repolist, Exam_Helper
from HonConnection import sendMsg, recvMsg, recvall, SendWithAES, RecieveWithAES, SendTupleWithAES, RecieveTupleWithAES

# Import Crypto Utility Files
from HonSecure import GenerateRandomKey, GenerateRandomSalt, GenerateHash, VerifyHash, GenerateHashWithSalt, VerifyHashWithSalt, GenerateSaltedHash, GenerateRSAKeys, ReadRSAKeysFromDisk, ReadRSAPublicKeyFromDisk, EncryptWithRSA, DecryptWithRSA, GenerateAESKey, EncryptWithAES, DecryptWithAES

# Meta Related Functions
METAPath = 'ServerData/'
UserMetaPath = METAPath + 'UserMETA.info'
UserPath = METAPath + 'Users/'

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

# Check if given userID exists
# e.g. print(CheckUserExist('s23456'))
def CheckUserExist(userID):
    userList = ReadMeta(UserMetaPath)
    for user in userList:
        if user == userID:
            return True
    return False

def GetUserData(userID):
    if CheckUserExist(userID):
        UserFilePath = UserPath + userID + '.info'
        exists = os.path.isfile(UserFilePath)
        if exists:
            UserData = ReadMeta(UserFilePath)
            return UserData
        else:
            return ['']

def CheckUserRole(userID):
    UserData = GetUserData(userID)
    if UserData is not None:
        return UserData[1]

def CheckRepoOwner(userID):
    UserRole = CheckUserRole(userID)
    return UserRole == 'RepoOwner'

def LoginUser(userID, password):
    if CheckUserExist(userID):
        UserData = GetUserData(userID)
        Hash = UserData[2]
        Salt = UserData[3]
        hashedPassword = GenerateHashWithSalt(pickle.dumps(password), pickle.dumps(Salt))
        if Hash == hashedPassword:
            return (True, Hash)
        else:
            return (False, '')

def GetUserPasswordHash(userID):
    UserData = GetUserData(userID)
    if UserData is not None:
        return UserData[2]
    
# General Server Utils

# Login
def Login(ownerID, passwordHash):
    #salt = "b'qSIkoYy8uPzdAGET9/5aRA=='"
    #ownerID = '1'
    #password = 'passwordServer' 
    #print('\n[Login]\nNote that your password will not show when you type for security reasons.\n')
    #ownerID = input('Enter your OwnerID: ')
    #password = getpass.getpass()
    serverIdentity = (ownerID, passwordHash)
    return serverIdentity

# Server Secure Connection
def EstablishSecureServerConnection(ownerID, passwordHash, socket, ServerKeyFolder, ClientPublicKeyFolder, data):

    # Recieve a session key which is decrypted using server private key.
    ServerKey = ReadRSAKeysFromDisk(ServerKeyFolder)
    EncryptedSessionKey = data
    SessionKey = DecryptWithRSA(ServerKey[0], EncryptedSessionKey)

    # Use Session Key to Descrypt and Encrypt from this point onwards.

    # Request Client Identity
    SendWithAES(socket, SessionKey, 'RequestClientIdentity')

    # Receive Client Identity, Compare UserID and Password Hash with server database.
    #ClientPasswordHash = '073f9dd9d134206828ea34f8d1c81b5150973fe7c470358f4e59528f8bc284a8'
    clientIdentity = RecieveTupleWithAES(socket, SessionKey)

    if len(clientIdentity) != 2:
        print('Recieved Unknown Request\nTerminating...')
        exit(-1)

    
    ClientPasswordHash = GetUserPasswordHash(clientIdentity[0])
    ClientPublicKeyFilePath = ClientPublicKeyFolder + clientIdentity[0]
    ClientPublicKey = ReadRSAPublicKeyFromDisk(ClientPublicKeyFilePath)


    # Send Server Repo Owner ID, Password Hash, Random Challenge String
    serverIdentity = Login(ownerID, passwordHash)

    # Challenge String
    challengeString = pickle.dumps(GenerateRandomSalt(16))
    encryptedChallengeString = EncryptWithRSA(ClientPublicKey, challengeString)

    payload = (encryptedChallengeString, serverIdentity)
    SendTupleWithAES(socket, SessionKey, payload)

    # Decrypt challenge string verify the challenge string matches.
    RecievedChallengeString = RecieveWithAES(socket, SessionKey)
    if challengeString != RecievedChallengeString:
        print('Recieved Bad Challenge String\nTerminating...')
        exit(-1)

    # Secure Connection Established
    SendWithAES(socket, SessionKey, b'Success')
    print('\nSecure Connection Established!\n')

    return (SessionKey)