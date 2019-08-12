
# Import
import sys, traceback
import os, re, time



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
        print('META File Is Missing\nTerminating...')
        exit(-1)

def GetServerMeta(metaFileLocation):
    tmp_list = ReadMeta(metaFileLocation)
    """
    Format of Server Meta:
    [IP Number]
    [Port Number]
    [Repo Owner ID]
    [Primary Admin ID]
    [Backup Admin IDs...]
    """
    ServerID       = tmp_list[0]
    PortNumber     = tmp_list[1]
    RepoOwnerID    = tmp_list[2]
    PrimaryAdminID = tmp_list[3]
    BackupAdminIDs = []

    if (len(tmp_list) > 4):
        for baID in range(4, (len(tmp_list)-1)):
            BackupAdminIDs.append(baID)




# Test Code
print(ReadMeta('Host_META.info'))

"""
self.server_port=tmp_list[0]
self.repo_owner_id=tmp_list[1]
self.p_admin_id=tmp_list[2]
self.others=tmp_list[3:] # The rest, if any, goes to the others
"""

"""
Host META
[IP Number]
[Port Number]
[Repo Owner ID]
[Primary Admin ID]
[Backup Admin IDs]
"""

"""
Client META
[IP Number]
[Port Number]
[Staff ID]
[Repo Owner ID]
[Primary Admin ID]
[Backup Admin IDs]
"""


"""
UserList META
[Repo Owner ID]
[UserID]
[More UserIDs ...]
"""


"""
RepoOwnerID META
[Repo Owner ID]
[Repo Owner Password Hash]
[Repo Owner Password Salt]
"""


"""
UserID META
[UserID]
[UserID Role] (RepoOwner/PrincipalAdmin/BackupAdmin/Examiner)
[UserID Password Hash]
[UserID Password Salt]
[UserID Module]
[More Modules...]
"""