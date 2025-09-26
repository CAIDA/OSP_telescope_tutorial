import socket
import fsspec
from pelicanfs.core import PelicanFileSystem,OSDFFileSystem
import argparse
from fsspec.implementations.http import HTTPFileSystem
import logging


logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True
requestsp_log = logging.getLogger("fsspec.pelican")
requestsp_log.setLevel(logging.DEBUG)
requestsp_log.propagate = True
http_client_log = logging.getLogger("http.client")
http_client_log.setLevel(logging.DEBUG)
http_client_log.propagate = True

def readhelloworld(input_path, token):
    #read the token file
    with open(token, "r") as f:
        token_str = f.read().strip()
    #create Authorization Bearer HTTP header
    options = {"headers": {"Authorization": f"Bearer {token_str}"}}

    #configurate PelicanFS
    fsosdf = PelicanFileSystem("pelican://osg-htc.org", headers={"Authorization": f"Bearer {token_str}"})

    #read the hello world file from OSDF
    with fsosdf.open(input_path, "rb",) as f:
        print(f.readline())


def main():
    parser = argparse.ArgumentParser(description="Read the hello world file and print it out.")
    parser.add_argument('-i', "--pcappath", help="Path to the hello world file")
    parser.add_argument('-t', "--token", help="Token for authentication")
    args = parser.parse_args()

    readhelloworld(args.pcappath, args.token)

if __name__ == "__main__":
    main()
