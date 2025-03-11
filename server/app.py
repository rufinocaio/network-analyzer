from scapy.all import *

def process_packet(packet):
    print(packet.summary)

def main():
    sniff(prn=process_packet, count=10000)

if __name__ == "__main__":
    main()