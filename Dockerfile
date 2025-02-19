# Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY app/requirements.txt .
RUN apt-get update && apt-get install -y tcpdump libpcap-dev
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0"]