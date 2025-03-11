# Usar uma imagem base leve do Ubuntu
FROM ubuntu:latest

# Atualizar o sistema e instalar dependências
RUN apt-get update && \
    apt-get install -y \
    python3 \
    python3-pip \
    tcpdump \
    net-tools \
    iputils-ping && \
    apt-get clean

# Instalar o Scapy
RUN apt install -y python3-scapy python3-requests

COPY . .

# Definir o comando padrão (opcional)
CMD ["bash"]