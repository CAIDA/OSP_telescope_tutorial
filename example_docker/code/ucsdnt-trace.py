import dpkt
import socket
import fsspec
#from pelicanfs.core import PelicanFileSystem,OSDFFileSystem
import argparse

#pelfs = PelicanFileSystem("pelican://osg-htc.org")
#hello_world = pelfs.cat('/ospool/uc-shared/public/OSG-Staff/validation/test.txt')
#print(hello_world)

#with fsspec.open("osdf:///ospool/uc-shared/public/OSG-Staff/validation/test.txt", "rb") as open_test:
#    line = open_test.readline()
#    print(line)


# Open the pcap file in binary read mode
#with pelfs.open("/home/cskpmok/ucsd-nt.1664589600.pcap", "rb") as f:
def readpcap(input_path, output_path, endcnt=10):
    count = 0
    mirai_syn_dict = {}
    with fsspec.open(input_path, "rb") as f:
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
    args = parser.parse_args()

    readpcap(args.pcappath,args.output, args.endcnt)

if __name__ == "__main__":
    main()