FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    tcpdump \
    net-tools \
    iputils-ping \
    iproute2 \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

# Configurar SSH
RUN mkdir /var/run/sshd
RUN echo 'root:password' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

EXPOSE 22 8501