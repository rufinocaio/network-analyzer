import requests
import time
import random
import os
import sys

def legitimate_traffic(target):
    # Usa a variável de ambiente definida no docker-compose
    print(f"Iniciando tráfego legítimo para {target}")
    
    while True:
        try:
            url = f"https://{target}"
            response = requests.get(url)
            print(f"Request legítimo: Status {response.status_code}")
            time.sleep(random.uniform(1, 5))
        except Exception as e:
            print(f"Erro na conexão: {e}")
            time.sleep(1)

if __name__ == "__main__":
    legitimate_traffic(sys.argv[1])