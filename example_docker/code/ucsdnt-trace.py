import dpkt
import socket
import fsspec
from pelicanfs.core import PelicanFileSystem,OSDFFileSystem
import argparse
from hashlib import md5
from Crypto.Cipher import AES

#pelfs = PelicanFileSystem("pelican://osg-htc.org")
#hello_world = pelfs.cat('/ospool/uc-shared/public/OSG-Staff/validation/test.txt')
#print(hello_world)

#with fsspec.open("osdf:///ospool/uc-shared/public/OSG-Staff/validation/test.txt", "rb") as open_test:
#    line = open_test.readline()
#    print(line)


# Open the pcap file in binary read mode
#with pelfs.open("/home/cskpmok/ucsd-nt.1664589600.pcap", "rb") as f:


class OpenSSLDecryptStream:
    def __init__(self, f, password: str):
        """
        f: file-like object with encrypted data
        password: passphrase string
        """
        self.f = f
        # Read OpenSSL salt header
        header = f.read(16)
        assert header[:8] == b"Salted__", "Missing OpenSSL salt header"
        salt = header[8:16]

        # Derive key/iv
        key, iv = self._evp_bytes_to_key(password.encode(), salt, 32, 16)
        self.cipher = AES.new(key, AES.MODE_CBC, iv)
        self.buffer = b""
        self.eof = False

    def _evp_bytes_to_key(self, password, salt, key_len, iv_len):
        dtot, d = b"", b""
        while len(dtot) < (key_len + iv_len):
            d = md5(d + password + salt).digest()
            dtot += d
        return dtot[:key_len], dtot[key_len:key_len+iv_len]

    def read(self, n=-1):
        """
        Provide a file-like read() interface for dpkt.
        """
        if self.eof:
            return b""

        out = b""
        while n < 0 or len(out) < n:
            chunk = self.f.read(4096)
            if not chunk:
                # Finalize: remove PKCS#7 padding
                decrypted = self.cipher.decrypt(self.buffer)
                pad_len = decrypted[-1]
                decrypted = decrypted[:-pad_len]
                self.buffer = b""
                self.eof = True
                out += decrypted
                break

            self.buffer += chunk
            # Keep at least one AES block (16B) in buffer
            keep = len(self.buffer) % 16
            to_dec = self.buffer[:-keep] if keep else self.buffer
            self.buffer = self.buffer[-keep:] if keep else b""
            out += self.cipher.decrypt(to_dec)

            if n > 0 and len(out) >= n:
                break

        return out



def readpcap(input_path, passkey, token,output_path, endcnt=10):
    count = 0
    mirai_syn_dict = {}
    with open(passkey, "r") as f:
        password = f.read().strip()
    #fsosdf = PelicanFileSystem("pelican://osg-htc.org")

    with fsspec.open(input_path, "rb") as f:
        if passkey:
            f = OpenSSLDecryptStream(f, password)
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.data.__class__.__name__ == 'IP':
                count += 1
                if count >= endcnt and endcnt > 0:
                    break
                ip = eth.data
                #print(f"Source IP: {socket.inet_ntoa(ip.src)}, Destination IP: {socket.inet_ntoa(ip.dst)}")
                if ip.data.__class__.__name__ == 'TCP':
                    tcp = ip.data
                    # Check if it's a TCP SYN packet (SYN flag set, ACK flag not set)
                    if (tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK):
                        # Convert destination IP to integer for comparison
                        dst_ip_int = int.from_bytes(ip.dst, byteorder='big')
                        if dst_ip_int == tcp.seq:
                            # Mirai SYN packet detected
                            mirai_syn_dict[socket.inet_ntoa(ip.src)] = mirai_syn_dict.get(socket.inet_ntoa(ip.src), 0) + 1

    print("Mirai SYN packet counts by source IP:")
    with open(output_path, "a") as out_f:
        for src_ip, syn_count in mirai_syn_dict.items():
            out_f.write(f"Source IP: {src_ip}, Mirai SYN Count: {syn_count}\n")



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
