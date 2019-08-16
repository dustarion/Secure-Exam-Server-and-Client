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
from datetime import datetime

# Import Common Utility Files
sys.path.append(os.path.abspath("../../Common"))
from examUtil import ExamHelper, Payload
from HonConnection import sendMsg, recvMsg, recvall, SendWithAES, RecieveWithAES, SendTupleWithAES, RecieveTupleWithAES

# Import Crypto Utility Files
from HonSecure import GenerateRandomKey, GenerateRandomSalt, GenerateHash, VerifyHash, GenerateHashWithSalt, VerifyHashWithSalt, GenerateSaltedHash, GenerateRSAKeys, ReadRSAKeysFromDisk, ReadRSAPublicKeyFromDisk, EncryptWithRSA, DecryptWithRSA, GenerateAESKey, EncryptWithAES, DecryptWithAES

# Meta Related Functions
METAPath = 'ServerData/'
UserMetaPath = METAPath + 'UserMETA.info'
UserPath = METAPath + 'Users/'
ExamPath = METAPath + 'Exams/'
LogFile = 'Server.log'

def LogMessage(message):
    # Log Format
    # Human Readable Timestamp | Message
    OutputLine = ''

    # Current Timestamp in Human Readable Format
    now = datetime.now()
    dt_object = datetime.timestamp(now)
    timestamp = datetime.fromtimestamp(dt_object)
    OutputLine += str(timestamp) + '\t'
    OutputLine += message + '\n'
    f=open(LogFile, "a+")
    f.write(OutputLine)
    f.close

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

def GetUserModules(userID):
    UserData = GetUserData(userID)
    if UserData is not None:
        if len(UserData) > 4:
            UserModules = []
            for i in range(4, len(UserData)-1):
                UserModules.append(UserData[i])
            return UserModules

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
    LogMessage('Secure Connection Established with Client')

    return (SessionKey)

def CheckIfFolderExists(folderPath):
    return os.path.exists(folderPath)

# Data is a tuple of the data you want to write to the specified META file.
def WriteToMeta(MetaFileLocation, Data):
    with open(MetaFileLocation,'w+') as meta:
        for row in Data:
            print(row, file = meta)
        meta.close()

def WriteToFile(FilePath, Data):
    f = open(FilePath, 'wb')
    f.write(Data)
    f.close

def ReadFromFile(FilePath):
    f = open(FilePath, 'rb')
    Data = f.read()
    f.close
    return Data

def GetExamMetaData(ModuleCode):
    ExamFolderFilePath = ExamPath + ModuleCode
    if CheckIfFolderExists(ExamFolderFilePath):
        return ReadFromFile(ExamFolderFilePath + '/META.info')
    else:
        print("File Does Not Exist\nTerminating...")
        exit(-1)

def GetExamData(ModuleCode):
    ExamFolderFilePath = ExamPath + ModuleCode
    if CheckIfFolderExists(ExamFolderFilePath):
        ExamMetaData = ReadMeta(ExamFolderFilePath + '/META.info')
        EncryptedExam = ReadFromFile(ExamFolderFilePath + '/EncryptedExam')
        EncryptedSoln = ReadFromFile(ExamFolderFilePath + '/EncryptedSoln')
        keys = ReadFromFile(ExamFolderFilePath + '/keys')
        return (ExamMetaData, EncryptedExam, EncryptedSoln, keys)


    else:
        print("File Does Not Exist\nTerminating...")
        exit(-1)

# Upload Request Recieved From Client
# Examiner wants to upload a paper!
# TODO: Log everything thx
def UploadRequestFromClient(RecievedPayload):
    staffID = RecievedPayload.staffID
    modCode = RecievedPayload.modCode
    examFn = RecievedPayload.examFn
    solFn = RecievedPayload.solFn
    examQns = RecievedPayload.examQns # contain the aes encrypted exam question paper in bytes 
    examSol = RecievedPayload.examSol  # contain the aes encrypted solution in bytes
    hybridKeys = RecievedPayload.hybridKeys

    FolderPath = ExamPath + modCode

    if not os.path.exists(FolderPath):
        os.mkdir(FolderPath)
        print("Directory " , FolderPath ,  " Created ")
    else:
        print("Directory " , FolderPath ,  " already exists")
        #TODO: Perform some form of archiving here.

    # Save the exam files to disk in this format
    """
    ModuleCode
        |_ META.info
        |_ EncryptedExam
        |_ EncryptedExamSolution
        |_ HybridKeys
    """
    FolderPath = ExamPath + modCode + '/'

    # Current Timestamp

    now = datetime.now()
    timestamp = datetime.timestamp(now)

    """
    timestamp = 1545730073
    dt_object = datetime.fromtimestamp(timestamp)
    print("dt_object =", dt_object)
    print("type(dt_object) =", type(dt_object))
    """

    # Write to META file
    # Format of META file
    """
    DateOfUpload
    UploaderID
    ModuleCode
    ExamFileName
    SolutionFilename
    """
    MetaFileLocation = FolderPath + 'META.info'
    WriteToMeta(MetaFileLocation, (timestamp, staffID, modCode, examFn, solFn))
    
    # Save Encrypted Exam and Encrypted Exam Solution
    EncryptedExamFileLocation = FolderPath + 'EncryptedExam'
    EncryptedSolnFileLocation = FolderPath + 'EncryptedSoln'
    WriteToFile(EncryptedExamFileLocation, pickle.dumps(examQns))
    WriteToFile(EncryptedSolnFileLocation, pickle.dumps(examSol))

    # Save the hybridkeys to disk
    HybridKeyFileLocation = FolderPath + 'keys'
    WriteToFile(HybridKeyFileLocation, pickle.dumps(hybridKeys))

    LogMessage('Successfully Recieved Payload from Client')

def  ListRequestFromClient(socket, key, RecievedHeader):
    # Determine if Admin or Examiner
    SenderID = RecievedHeader.uploaderID
    SenderRole = CheckUserRole(SenderID)

    DirectoryList = os.listdir(ExamPath)
    ModuleList = []


    if SenderRole == 'Examiner':
        # Examiner
        UserModules = GetUserModules(SenderID)
        for item in DirectoryList:
        # Ignore if not module folder
            if item[0] == 'S':
                # Check if match userModules
                if item[0] in UserModules:
                    ModuleList.append(item)
        
    else:
        #Admin or Backup Admin
        # List all the files in database
        for item in DirectoryList:
        # Ignore if not module folder
            if item[0] == 'S':
                ModuleList.append(item)

    ModuleDataList = []
    for module in ModuleList:
        MetaData = GetExamMetaData(module)
        TimeStamp = datetime.fromtimestamp(MetaData[0])
        RepoContent = "Module Code:({}) \tUploaded By:({}) \tLast_Modified:({})\n".format(MetaData[2], MetaData[1], TimeStamp)
        ModuleDataList.append(RepoContent)

    SendTupleWithAES(socket, key, ModuleDataList)

    # Should Recieve a successful response!
    request = RecieveWithAES(socket, key)
    if request != b'SuccessfullyRecievedExamList':
        print('Recieved Unknown Request\nTerminating...')
    LogMessage('Client Successfully Recieved Exam List')

def DownloadRequestFromClient(socket, key, RecievedHeader):
    # Determine if Admin or Examiner
    SenderID = RecievedHeader.uploaderID
    SenderRole = CheckUserRole(SenderID)
    ModuleCode = RecievedHeader.modCode

    #(ExamMetaData, EncryptedExam, EncryptedSoln, keys)
    ExamData = GetExamData(ModuleCode)

    SendTupleWithAES(socket, key, ExamData)

    LogMessage('Sent Data to Client')

# Exam Uploading / Downloading!
def RecieveRequestFromClient(socket, key):

    RecievedPayload = RecieveTupleWithAES(socket, key)
    RecievedHeader = RecievedPayload[0]
    RecievedPayload = RecievedPayload[1]

    SenderID = RecievedHeader.uploaderID
    SenderRole = CheckUserRole(SenderID)

    RequestType = RecievedHeader.requestType
    LogMessage('Recieved Request From Client: ' + str(RequestType) + ' From: ' + str(SenderID))

    if RequestType == 'U':
        # Upload Request
        print('Upload Request from Client')
        # Check if Sender is Allowed
        if SenderRole == 'Examiner':
            UploadRequestFromClient(RecievedPayload)
            SendWithAES(socket, key, b'SuccessfullyRecievedExamPayload')
        else:
            print("Client Not Authorised To Upload\nTerminating...")
            exit(-1)

    elif RequestType == 'D':
        # Download Request
        DownloadRequestFromClient(socket, key, RecievedHeader)
        if SenderRole == 'PrincipalAdmin' or SenderRole == 'BackupAdmin':
            print('Download Request from Client')
        else:
            print("Client Not Authorised To Download\nTerminating...")
            exit(-1)

    elif RequestType == 'L':
        # List Request
        print('List Request from Client')
        if SenderRole == 'Examiner' or SenderRole == 'PrincipalAdmin' or SenderRole == 'BackupAdmin':
            ListRequestFromClient(socket, key, RecievedHeader)
        else:
            print("Client Not Authorised To Upload\nTerminating...")
            exit(-1)


    else:
        # Unknown Request
        print('Recieved Unknown Request\nTerminating...')
        exit(-1)
