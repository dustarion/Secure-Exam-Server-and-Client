import sys, traceback 
sys.path.append("..") # Adds parent directory to python3 modules path
import os , re , time
import socket
import socketserver
import pickle
from exam_util_v1_2 import Payload, Con_header, Resp_header, Repolist, Exam_Helper

class MyTCPHandler(socketserver.BaseRequestHandler):

    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def setup(self):
        # this will be invoked once at the beginnig of the instantiation.
        #print("setup is invoked")
        self.buffer_size=Exam_Helper.block_size
        self.meta = Security_Check_Point()

    def get_payload(self,req_header):
        print(f"entering get_payload of {req_header.mod_code}, uploaded by : {req_header.uploader_id}")
        scp=self.meta
        files = [f for f in os.listdir('.') if os.path.isfile(f) and \
                 f.endswith(req_header.uploader_id+'.dat') and f.startswith(req_header.mod_code)]
        #print(files)
        if len(files) != 1 :
            return None
        ########################
        try:
            with open(files[0],"rb") as f1:
                payload_bytes = f1.read() # read in the entire file and store it in payload_bytes
                f1.close()
            return payload_bytes
        except:
            print(f"Serious FILE I/O error. Cannot open/read from {files[0]}")
            return None
        
    def send_payload(self,pload_bytes):
        try:
            # now waiting for ready to receive signal from the client 
            ack = str(self.request.recv(self.buffer_size), "utf-8")
            if ack != "ack":
                print("client abort")
                return
            print("Got the ack. Send the payload now")
            Exam_Helper.block_send(self.request,pload_bytes,self.buffer_size)
        except socket.timeout as tmerr:
            print("handler timout and exits")
            
    def get_pload_list(self,staff_id):
        #print(f"in get_pload_list staff_id is {staff_id}")
        def get_Playload_Info(fname,staff_id):
            # get_Playload_Info is a sub function of get_pload_list()
            # Playload Info includes the module code, the examiner id and the upload date/time
            scp=self.meta
            output=""
            id=re.search(r"\.([^\.]*)",fname) # search for staff_id from the filename.
            if id and id.lastindex == 1:
                if staff_id == scp.p_admin_id or staff_id in scp.others or staff_id == id.group(1):
                    # retrieve all the files for admin or user own files.
                    mod_code=re.search(r"^[^\.]*",fname)
                    if mod_code:
                        t=os.stat(fname).st_mtime
                        output=f"{mod_code.group(0):20} {id.group(0)[1:]:10} {time.ctime(t):30}\n"
            return output
            
        result=""
        files = [f for f in os.listdir('.') if os.path.isfile(f) and f.endswith('.dat')]
        #print(files) # all the matched files.
        for f in files:
            result=result+get_Playload_Info(f,staff_id)
        repo=Repolist() # create a default (and empty) Repolist object.
        if len(result) > 0:
            repo.status="ok"
            repo.content=f"{'Module_Code':20} {'Upload_By':10} {'Last_Modified':30}\n"+result
        return pickle.dumps(repo)
    
   
            
    def handle_upload(self,req_header):
        try:
            p_len = req_header.payload_size
            # print(f"payload size: {p_len}") # for debugging.
            # send a positive ack to the client
            scp=self.meta       # Retrieve the server owner, exam admid ids.
            resp_header= Resp_header()
            resp_header.resp_type='ok'
            # The following responses may provide the info for the client to encrypt the
            # payload in such a way that, all the exam admins can decrypt the payload at their ends.
            resp_header.p_admin_id=scp.p_admin_id  
            resp_header.others = scp.others
            # send the resp_header now.
            Exam_Helper.block_send(self.request,pickle.dumps(resp_header),self.buffer_size) 
            # now is waiting for the payload from the client.
            pload_bytes = Exam_Helper.block_recv(self.request,p_len,self.buffer_size)
            pload = pickle.loads(pload_bytes)
            if type(pload) is Payload:
                print("Payload has just arrived")
                print(f"staff id : {pload.staff_id}")
                print(f"module code : {pload.mod_code}")
                print(f"Exam paper file name: {pload.exam_fn}")
                print(f"Exam solution file name : {pload.sol_fn}")
                # now write payload bytes to a binary file.
                with open(pload.mod_code+'.'+pload.staff_id+".dat","wb") as outf:
                    outf.write(pload_bytes)
                # send back an acknowledgement message to the client
                self.request.sendall(b"upload operation has been completed successfully")
            else:
                #print(f"pload object type => {type(pload)}")
                # send back an error message to the client
                self.request.sendall(b"upload operation has been failed!!!")
        except socket.timeout as tmerr:
            print("handler timout and exits")
            pass
        except:
            print(f"handler exists due to unexpected error : {sys.exc_info()[0]}")
            traceback.print_exc(file=sys.stdout)
  
    def handle_retrieval(self,req_header):
        print(f"{req_header.requester_id} is requesting to retrieve the payload of {req_header.mod_code}")
        scp=self.meta
        resp_header= Resp_header()
        if req_header.requester_id == scp.p_admin_id or req_header.requester_id in scp.others:
            payload_bytes=self.get_payload(req_header)
            if payload_bytes != None:
                resp_header.resp_type='ok'
                resp_header.payload_size=len(payload_bytes)
                resp_bytes=pickle.dumps(resp_header)
                print("sending resp_header to client")
                self.request.sendall(resp_bytes)
                self.send_payload(payload_bytes)
                return
        resp_header.resp_type='rejected'
        resp_bytes=pickle.dumps(resp_header)
        self.request.sendall(resp_bytes)

    def handle_get_payload_listing(self,staff_id):
        try:
            rpo_bytes=self.get_pload_list(staff_id) # repo_bytes is from a Repolist object.
            #it contains a status , and a content field
            #print("rpo_bytes is ready. Send it now")
            Exam_Helper.block_send(self.request,rpo_bytes,self.buffer_size)
        except socket.timeout as tmerr:
            print("handler timout and exits")
        except:
            print(f"handler exists due to unexpected error : {sys.exc_info()[0]}")
    
    def handle(self):
        # self.request is the TCP socket connected to the client
        # Set a timeout value on this socket connection, to avoid
        # this server to be held up by a malfunction client.  
        self.request.settimeout(Exam_Helper.timeout_in_seconds)
        try:
            print(f"Connection from {self.client_address[0]}:{self.client_address[1]}")
            self.data = self.request.recv(self.buffer_size).strip()
            if self.data == None:
                return() 
            # self.data should contain a valid Con_header object
            req_header = pickle.loads(self.data)
            if type(req_header) is Con_header and req_header.request_type in ['u','r','L']:
                if req_header.request_type=='u':
                    self.handle_upload(req_header)
                elif req_header.request_type =='r':
                    self.handle_retrieval(req_header)
                else: # must be 'L'
                    self.handle_get_payload_listing(req_header.requester_id)
            else:
                #invalid request
                print(f"Handler exits due to invalid request: {req}")
                return()
                
        except socket.timeout as tmerr:
            print("handler timout and exits")
        #except:
        #    print(f"handler exists due to unexpected error : {sys.exc_info()[0]}")
 
    def finish(self):
        print("reaching finish() of the handler")
        return socketserver.BaseRequestHandler.finish(self)