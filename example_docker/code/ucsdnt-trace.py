import dpkt
import socket
import fsspec
from pelicanfs.core import PelicanFileSystem,OSDFFileSystem
import argparse
from hashlib import md5
from Crypto.Cipher import AES


class OpenSSLDecryptStream:
    """
    File-like wrapper that decrypts OpenSSL "enc -aes-256-cbc -salt -md md5" streams
    incrementally and safely for consumers like dpkt.pcap.Reader.
    """
    def __init__(self, f, password, chunk_size=4096):
        self.f = f
        self.chunk_size = chunk_size

        header = f.read(16)
        if len(header) < 16 or header[:8] != b"Salted__":
            raise ValueError("Missing or invalid OpenSSL salt header")
        salt = header[8:16]

        key, iv = self._evp_bytes_to_key(password.encode("utf-8"), salt, 32, 16)
        self.cipher = AES.new(key, AES.MODE_CBC, iv)

        # Encrypted bytes not yet decrypted (until full 16-byte blocks)
        self.enc_buffer = b""
        # Decrypted plaintext buffer ready to serve
        self.plain_buffer = bytearray()
        self.eof = False

    @staticmethod
    def _evp_bytes_to_key(password, salt, key_len, iv_len):
        dtot = b""
        d = b""
        while len(dtot) < (key_len + iv_len):
            d = md5(d + password + salt).digest()
            dtot += d
        return dtot[:key_len], dtot[key_len:key_len+iv_len]

    def _decrypt_full_blocks(self):
        """Decrypt all full 16-byte blocks in enc_buffer and append to plain_buffer."""
        if len(self.enc_buffer) < 16:
            return
        full_len = len(self.enc_buffer) - (len(self.enc_buffer) % 16)
        to_dec = self.enc_buffer[:full_len]
        self.enc_buffer = self.enc_buffer[full_len:]
        if to_dec:
            self.plain_buffer.extend(self.cipher.decrypt(to_dec))

    def _finalize(self):
        """Handle last encrypted block, strip PKCS#7 padding safely."""
        if not self.enc_buffer:
            return
        decrypted = self.cipher.decrypt(self.enc_buffer)
        if decrypted:
            pad_len = decrypted[-1]
            # check PKCS#7 padding validity
            if 1 <= pad_len <= 16 and decrypted.endswith(bytes([pad_len]) * pad_len):
                decrypted = decrypted[:-pad_len]
            self.plain_buffer.extend(decrypted)
        self.enc_buffer = b""

    def read(self, n=-1):
        """
        Read up to n bytes of plaintext. If n < 0, read all remaining plaintext.
        """
        if n == 0:
            return b""

        if n < 0:
            # Read entire stream
            while not self.eof:
                chunk = self.f.read(self.chunk_size)
                if not chunk:
                    self._finalize()
                    self.eof = True
                    break
                self.enc_buffer += chunk
                self._decrypt_full_blocks()

            data = bytes(self.plain_buffer)
            self.plain_buffer.clear()
            return data

        # Read up to n bytes
        while len(self.plain_buffer) < n and not self.eof:
            chunk = self.f.read(self.chunk_size)
            if not chunk:
                self._finalize()
                self.eof = True
                break
            self.enc_buffer += chunk
            self._decrypt_full_blocks()

        if not self.plain_buffer:
            return b""

        if len(self.plain_buffer) >= n:
            # enough data to satisfy request
            data = bytes(self.plain_buffer[:n])
            del self.plain_buffer[:n]
            return data

        # Not enough data left (EOF case)
        if self.eof:
            # If fewer than n bytes remain, discard them so dpkt doesn't see a truncated header
            self.plain_buffer.clear()
            return b""

        # fallback (shouldn't really happen)
        data = bytes(self.plain_buffer)
        self.plain_buffer.clear()
        return data
    def readable(self):
        return True

def readpcap(input_path, passkey, token,output_path, endcnt=10):
    count = 0
    syn_dict = {}
    #read the token file
    with open(token, "r") as ft:
        token_str = ft.read().strip()

    #configurate PelicanFS
    fsosdf = PelicanFileSystem("pelican://osg-htc.org", headers={"Authorization": f"Bearer {token_str}"})

    #read the decryption key
    with open(passkey, "r") as fpass:
        password = fpass.read().strip()
    with fsosdf.open(input_path, "rb") as fin:
#    with open(input_path, "rb") as fin:
        f = OpenSSLDecryptStream(fin, password)
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if eth.data.__class__.__name__ == 'IP':
                if count >= endcnt and endcnt > 0:
                    break
                count += 1
                ip = eth.data
                print(f"Source IP: {socket.inet_ntoa(ip.src)}, Destination IP: {socket.inet_ntoa(ip.dst)}")
                if ip.data.__class__.__name__ == 'TCP':
                    tcp = ip.data
                    # Check if it's a TCP SYN packet (SYN flag set, ACK flag not set)
                    if (tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK):
                        # Convert destination IP to integer for comparison
                        # TCP SYN packet count
                        syn_dict[socket.inet_ntoa(ip.src)] = syn_dict.get(socket.inet_ntoa(ip.src), 0) + 1

    print("Outputing SYN packet counts by source IP...")
    with open(output_path, "a") as out_f:
        for src_ip, syn_count in syn_dict.items():
            out_f.write(f"Source IP: {src_ip}, SYN Count: {syn_count}\n")



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
