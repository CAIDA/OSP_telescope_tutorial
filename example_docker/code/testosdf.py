import dpkt
import socket
import fsspec
from pelicanfs.core import PelicanFileSystem,OSDFFileSystem
import argparse
from hashlib import md5
from Crypto.Cipher import AES
from fsspec.implementations.http import HTTPFileSystem

#pelfs = PelicanFileSystem("pelican://osg-htc.org")
#hello_world = pelfs.cat('/ospool/uc-shared/public/OSG-Staff/validation/test.txt')
#print(hello_world)

#with fsspec.open("osdf:///ospool/uc-shared/public/OSG-Staff/validation/test.txt", "rb") as open_test:
#    line = open_test.readline()
#    print(line)


# Open the pcap file in binary read mode
#with pelfs.open("/home/cskpmok/ucsd-nt.1664589600.pcap", "rb") as f:



def readpcap(input_path, passkey, token,output_path, endcnt=10):
    with open(token, "r") as f:
        token_str = f.read().strip()
    options = {"headers": {"Authorization": f"Bearer {token_str}"}}
    #fsosdf = fsspec.filesystem("pelican", host="osg-htc.org", headers={"Authorization": f"Bearer {token_str}"})
    
    fsosdf = PelicanFileSystem("pelican://osg-htc.org", headers={"Authorization": f"Bearer {token_str}"})

    #with fsspec.open(input_path, "rb") as f:
    with fsosdf.open(input_path, "rb",) as f:
        print(f.readline())


def main():
    parser = argparse.ArgumentParser(description="Read a pcap file and print packet info.")
    parser.add_argument('-i', "--pcappath", help="Path to the pcap file")
    parser.add_argument('-c',"--endcnt", type=int, default=10, help="Number of packets to process (default: 10)")
    parser.add_argument('-o', "--output", help="Path to the output file")
    parser.add_argument('-p', "--password", help="Password file for decryption if needed")
    parser.add_argument('-t', "--token", help="Token for authentication if needed")
    args = parser.parse_args()

    readpcap(args.pcappath, args.password, args.token,args.output, args.endcnt)

if __name__ == "__main__":
    main()
