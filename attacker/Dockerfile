# Usar uma imagem base leve do Ubuntu
FROM ubuntu:latest

# Atualizar o sistema e instalar dependências
RUN apt-get update && \
    apt-get install -y \
    python3-full \
    tcpdump \
    net-tools \
    iputils-ping \
    iproute2 \
    openssh-server &&\
    apt-get clean 

RUN python3 -m venv /opt/venv

COPY requirements.txt .
RUN /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY . .

# Definir o comando padrão (opcional)
CMD ["bash"]