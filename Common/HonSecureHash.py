# Python program to find SHA256 hash string of a file
import hashlib

providedhash = input ("Please enter the hash of the file you would like to verify!")
filename = input("Enter the input file name: ")
sha256_hash = hashlib.sha256()
with open(filename, "rb") as f:
    # Read and update hash string value in blocks of 4K
    for byte_block in iter(lambda: f.read(4096), b""):
        sha256_hash.update(byte_block)
    print(sha256_hash.hexdigest())

if providedhash != sha256_hash.hexdigest():
    print("The hash that you have provided does not match the hash that we have just calculated!")
else:
    print("The hash that you have provided matches the hash that we have just calcuated!")
