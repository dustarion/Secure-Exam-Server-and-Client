# ST2504 - ACG assginment2
#   - ensure  block_recv is using timeout to detect end of data stream.
#   -slow down the block_send speed to avoid TCP errors.

import os
import socket
import readline
from time import sleep

# Exam Helper Class
class ExamHelper():
    def MyInput(prompt,defval=""):
        # A class function that help to improve input() (provided default value)
        def hook():
            readline.insert_text(defval)
            if os.name != "nt": # windows does not have redisplay() nor require to use redisplay()
                readline.redisplay()
        readline.set_pre_input_hook(hook)    
        ans=input(f"{prompt}")
        readline.set_pre_input_hook() # CLEAR THE preset 
        if (ans == None or len(ans) ==0):
            return ""
        return ans

# Data Classes
class PayloadKey():
    def __init__(self):
        self.staffID=''
        self.encryptedKey='' # AES Key Encrypted with the public key of the given staff.

class Payload():
    # A data class to encapusule all the Examination Paper Repo Payload
    def __init__(self):
        # META Information
        self.staffID=''
        self.modCode=''
        self.examFn=''
        self.solFn=''
        self.examQns = '' # contain the aes encrypted exam question paper in bytes 
        self.examSol =''  # contain the aes encrypted solution in bytes
        self.hybridKeys = [PayloadKey]


# Headers

class UploadHeader():
    # A data class to encapusule the upload request header
    # A client sends in its request using an object of Con_header
    def __init__(self,reqID='',reqType='L'):
        self.requestType=reqType    # List, Upload, or Retrieve (L/U/R)
        self.requesterID=reqID   # the staff id of the requester
        self.modCode=''        # optional field to specify the target module.
        self.uploaderID=''     # optional filed only required by the retrieve payload request

class RespHeader():
    # A data class to encapusule the connection reponse header
    # The server sends its response to a client request using an object of Resp_header
    def __init__(self,respT='ok'):
        self.resp_type=respT    # 'ok','reject'
        self.p_admin_id=''   # optional field - contains the principal exam admin id   
        self.others = []     # optional field - contains a list of backup exam admin ids.
        self.payload_size=0  # optional field - contains the payload_size for a retrieve request.

    