import requests
import time
import random
import os

def legitimate_traffic():
    # Usa a variável de ambiente definida no docker-compose
    server_url = os.getenv('SERVER_URL', 'http://server:80')
    print(f"Iniciando tráfego legítimo para {server_url}")
    
    while True:
        try:
            response = requests.get(server_url)
            print(f"Request legítimo: Status {response.status_code}")
            time.sleep(random.uniform(1, 5))
        except Exception as e:
            print(f"Erro na conexão: {e}")
            time.sleep(1)

if __name__ == "__main__":
    legitimate_traffic()