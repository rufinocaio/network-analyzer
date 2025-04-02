import pandas as pd
import json
import time
import subprocess
import os
import sys
import argparse
from datetime import datetime

# Adicionar diretório pai ao PATH para importar módulos
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class DetectionEvaluator:
    def __init__(self, target_ip, test_duration=300, attack_interval=30):
        self.target_ip = target_ip
        self.test_duration = test_duration  
        self.attack_interval = attack_interval
        self.results = {
            "port_scan": {"sent": 0, "detected": 0},
            "syn_flood": {"sent": 0, "detected": 0},
            "icmp_flood": {"sent": 0, "detected": 0},
            "udp_flood": {"sent": 0, "detected": 0},
            "dns_amplification": {"sent": 0, "detected": 0},
            "slowloris": {"sent": 0, "detected": 0}
        }
        self.attack_list = []
        self.timestamp_log = []
    
    def run_attack(self, attack_type):
        """Executa um ataque específico utilizando o script de ataque"""
        cmd = [
            "./.venv/bin/python3", 
            "./attacker/attack.py", 
            self.target_ip,
            "-t", "10",  # Duração curta para cada teste
            "--attack-type", attack_type  # Precisaria adicionar este parâmetro ao attack.py
        ]
        
        print(f"Iniciando ataque: {attack_type}")
        self.results[attack_type]["sent"] += 1
        
        # Registra o timestamp de início do ataque
        start_time = time.time()
        self.timestamp_log.append({
            "attack_type": attack_type,
            "start_time": start_time,
            "end_time": None
        })
        
        # Executa o ataque
        subprocess.run(cmd, check=True)
        
        # Registra o timestamp de fim do ataque
        self.timestamp_log[-1]["end_time"] = time.time()
        
        # Espera um pouco para o detector processar
        time.sleep(5)
        
        # Verifica se o ataque foi detectado
        self.check_detection(attack_type, start_time)
    
    def check_detection(self, attack_type, start_time):
        """Verifica se o ataque foi detectado corretamente"""
        # Mapeia os tipos de ataque para os nomes no detector
        attack_type_map = {
            "port_scan": "Port Scanning",
            "syn_flood": "SYN Flood",
            "icmp_flood": "ICMP Flood",
            "udp_flood": "UDP Flood",
            "dns_amplification": "DNS Amplification",
            "slowloris": "Slowloris"
        }
        
            # Lê a lista de ataques detectados do arquivo
        try:
            with open("detected_attacks.json", "r") as f:
                attack_list = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            attack_list = []

        # Procura por detecções do tipo correto após o início do ataque
        for alert in attack_list:
            if (alert["type"] == attack_type_map[attack_type] and 
                alert["timestamp"] >= start_time):
                self.results[attack_type]["detected"] += 1
                print(f"✅ Ataque {attack_type} detectado corretamente!")
                return
        
        print(f"❌ Ataque {attack_type} NÃO foi detectado!")
    
    def run_test_suite(self):
        """Executa uma série de testes para todos os tipos de ataque"""
        attack_types = list(self.results.keys())
        
        print(f"Iniciando suite de testes com duração de {self.test_duration} segundos")
        print(f"Alvo: {self.target_ip}")
        
        start_time = time.time()
        
        while time.time() - start_time < self.test_duration:
            for attack_type in attack_types:
                self.run_attack(attack_type)
                time.sleep(self.attack_interval)
                
                # Verifica se já passou o tempo total
                if time.time() - start_time >= self.test_duration:
                    break
        
        self.generate_report()
    
    def generate_report(self):
        """Gera um relatório com os resultados dos testes"""
        print("\n" + "="*50)
        print("RELATÓRIO DE DETECÇÃO DE ATAQUES")
        print("="*50)
        
        overall_sent = 0
        overall_detected = 0
        
        for attack_type, data in self.results.items():
            sent = data["sent"]
            detected = data["detected"]
            overall_sent += sent
            overall_detected += detected
            
            detection_rate = (detected / sent * 100) if sent > 0 else 0
            print(f"{attack_type.upper()}: {detected}/{sent} detectados ({detection_rate:.1f}%)")
        
        overall_rate = (overall_detected / overall_sent * 100) if overall_sent > 0 else 0
        print("-"*50)
        print(f"TAXA GERAL DE DETECÇÃO: {overall_detected}/{overall_sent} ({overall_rate:.1f}%)")
        
        # Salva resultados em um arquivo JSON
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        with open("detection_report.json", "w") as f:
            json.dump({
                "results": self.results,
                "overall_rate": overall_rate,
                "timestamp_log": self.timestamp_log
            }, f, indent=4)
        
        print("\nRelatório salvo em detection_report.json")
        
        # Também gera um relatório CSV
        rows = []
        for attack_type, data in self.results.items():
            detection_rate = (data["detected"] / data["sent"] * 100) if data["sent"] > 0 else 0
            rows.append({
                "Tipo de Ataque": attack_type,
                "Enviados": data["sent"],
                "Detectados": data["detected"],
                "Taxa de Detecção (%)": detection_rate
            })
        
        df = pd.DataFrame(rows)
        df.to_csv("detection_report.csv", index=False)
        print("Relatório CSV salvo em detection_report.csv")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Avaliador de detecção de ataques")
    parser.add_argument("target", help="Endereço IP do alvo")
    parser.add_argument("-t", "--time", type=int, default=300, 
                        help="Duração total dos testes em segundos (padrão: 300)")
    parser.add_argument("-i", "--interval", type=int, default=30,
                        help="Intervalo entre ataques em segundos (padrão: 30)")
    args = parser.parse_args()
    
    evaluator = DetectionEvaluator(args.target, args.time, args.interval)
    evaluator.run_test_suite()