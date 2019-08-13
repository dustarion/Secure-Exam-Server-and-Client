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
from examUtil import PayloadKey, Payload, UploadHeader, RespHeader  #, Con_header, Resp_header, Repolist, Exam_Helper
from HonConnection import sendMsg, recvMsg, recvall, SendWithAES, RecieveWithAES, SendTupleWithAES, RecieveTupleWithAES

# Import Crypto Utility Files
from HonSecure import GenerateRandomKey, GenerateRandomSalt, GenerateHash, VerifyHash, GenerateHashWithSalt, VerifyHashWithSalt, GenerateSaltedHash, GenerateRSAKeys, ReadRSAKeysFromDisk, ReadRSAPublicKeyFromDisk, EncryptWithRSA, DecryptWithRSA, GenerateAESKey, EncryptWithAES, DecryptWithAES

# Meta Related Functions
METAPath = '../ClientData/'
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

def GetAdminIDs():
    userList = ReadMeta(UserMetaPath)
    adminList = []
    for user in userList:
        role = CheckUserRole(user)
        if role == 'PrincipalAdmin' or role == 'BackupAdmin':
            adminList.append(user)
    return adminList

# Get the public key of the specified user.
def GetUserKey(userID):
    FolderKeyPath = METAPath + 'PublicKeys/' + userID
    return ReadRSAPublicKeyFromDisk(FolderKeyPath)

# Test Code
# print(GetUserKey('s34567').exportKey())

# Login
def Login(clientID, passwordHash):
    #salt = "KE9C2mx6225XcC5isRIa/g=="
    #userID = '2'
    #password = 'passwordClient' 
    #print('\n[Login]\nNote that your password will not show when you type for security reasons.\n')
    #userID = input('Enter your UserID: ')
    #password = getpass.getpass()

    clientIdentity = (clientID, passwordHash)

    return clientIdentity


# Client Secure Connection
def EstablishSecureClientConnection(repoOwnerID, clientID, passwordHash, socket, ClientKeyFolder, ServerPublicKeyFolder):
    # Generate Session Key
    SessionKey = GenerateAESKey()

    # Encrypt Session Key with Public Key of Server
    ServerPublicKey = ReadRSAPublicKeyFromDisk(ServerPublicKeyFolder)
    TempPayload = EncryptWithRSA(ServerPublicKey, SessionKey)

    sendMsg(socket, TempPayload)

    # Use Session Key to Descrypt and Encrypt from this point onwards.

    # Recieve request for client identity
    request = RecieveWithAES(socket, SessionKey)
    if request != b'RequestClientIdentity':
        print('Recieved Unknown Request\nTerminating...')
        exit(-1)
    
    # Send Clients UserID and Password Hash
    clientIdentity = Login(clientID, passwordHash)

    SendTupleWithAES(socket, SessionKey, clientIdentity)

    # Recieve Repo Owner ID and Password Hash (Also a random challenge string)
    # Compare with Local Database
    #ServerPasswordHash = 'e541fc35f5a53d83b815042a21af51fba903c03321c61f7ca1d883f9bf52df63' 
    ServerPasswordHash = GetUserPasswordHash(repoOwnerID)
    RecievedPayload = RecieveTupleWithAES(socket, SessionKey)
    EncryptedChallengeString = RecievedPayload[0]
    ServerIdentity = RecievedPayload[1]
    if len(ServerIdentity) != 2:
        print('Recieved Unknown Request\nTerminating...')
        exit(-1)
    
    # Encrypt Challenge String with Private Key.
    ClientKey = ReadRSAKeysFromDisk(ClientKeyFolder)
    ChallengeString = DecryptWithRSA(ClientKey[0], EncryptedChallengeString)

    # Send to Server
    SendWithAES(socket, SessionKey, ChallengeString)

    # Recieve successful response.
    response = RecieveWithAES(socket, SessionKey)
    if response != b'Success':
        print('Recieved Unknown Request\nTerminating...')
        exit(-1)

    # Secure Connection Established
    print('\nSecure Connection Established!\n')

    return (SessionKey)

# Exam Uploading / Downloading!
def UploadExamToServer(staffID, modCode):

    # Force Feed Temp
    ExamFilePath = '../Uploads/ST2504/AY20132014S2_ST2504_Exam.v1.pdf'
    SolnFilePath = '../Uploads/ST2504/AY20132014S2_ST2504_Sol.v1.pdf'
    AdminList = GetAdminIDs()
    AdminKeys = []
    for admin in AdminList:
        tmp = PayloadKey()
        tmp.staffID = admin
        row = (tmp, GetUserKey(admin))
        AdminKeys.append(row)

    # Convert PDF to Bytes
    ExamQnBytes = open(ExamFilePath, 'rb').read()
    ExamSolnBytes = open(SolnFilePath, 'rb').read()

    # Generate a AES key to seal the files.
    SealKey = GenerateAESKey()

    # Format: (iv, cipherData)
    EncryptedExamQn = EncryptWithAES(SealKey, ExamQnBytes)
    EncryptedExamSoln = EncryptWithAES(SealKey, ExamSolnBytes)

    # Encrypt the aes keys with rsa for each admin.
    for row in AdminKeys:
        pubKey = row[1]
        newKey = EncryptWithRSA(pubKey, SealKey)
        row[0].encryptedKey = newKey

    HybridKeys = []
    for row in AdminKeys:
        HybridKeys.append(row[0])

    # Construct a Payload Object
    PayloadToSend = Payload()
    PayloadToSend.staffID = staffID
    PayloadToSend.modCode = 'ST2504'
    PayloadToSend.examFn = 'AY20132014S2_ST2504_Exam.v1.pdf'
    PayloadToSend.solFn = 'AY20132014S2_ST2504_Sol.v1.pdf'
    PayloadToSend.examQns = ExamQnBytes
    PayloadToSend.examSol = ExamSolnBytes
    PayloadToSend.hybridKeys = HybridKeys
    







# Test Code
UploadExamToServer()

#DecryptedExamQn = DecryptWithAES(SealKey, EncryptedExamQn[0], EncryptedExamQn[1])
# Convert Bytes to PDF
    #f = open(ExamQnLocation2, 'wb')
    #f.write(ExamBytes)

