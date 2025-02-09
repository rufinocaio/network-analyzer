import threading
import time
import pandas as pd
import streamlit as st
import plotly.express as px
from scapy.all import sniff
from datetime import datetime

st.set_page_config(layout="wide")

# Variáveis globais
packet_list = []
attack_list = []
sniffing = True
port_scan_tracker = {}
syn_flood_tracker = {}
icmp_flood_tracker = {}
start_time = None

def format_timestamp(epoch_time):
    return datetime.fromtimestamp(epoch_time).strftime("%Y-%m-%d %H:%M:%S")

# Processamento de pacotes
def process_packet(packet):
    global packet_list, attack_list, start_time

    # Se o tempo inicial ainda não foi definido, defina-o como o tempo do primeiro pacote
    if start_time is None:
        start_time = packet.time

    # Calcula o tempo relativo em relação ao início da captura
    relative_time = packet.time - start_time

    packet_info = {}

    # Camada Ethernet
    if packet.haslayer("Ether"):
        packet_info.update({
            "src_mac": packet["Ether"].src,
            "dst_mac": packet["Ether"].dst,
            "eth_type": packet["Ether"].type
        })

    # Camada IP
    if packet.haslayer("IP"):
        packet_info.update({
            "src_ip": packet["IP"].src,
            "dst_ip": packet["IP"].dst,
            "protocol": "IPv4"
        })
    elif packet.haslayer("IPv6"):
        packet_info.update({
            "src_ip": packet["IPv6"].src,
            "dst_ip": packet["IPv6"].dst,
            "protocol": "IPv6"
        })

    # Camada TCP/UDP
    if packet.haslayer("TCP"):
        tcp = packet["TCP"]
        packet_info.update({
            "src_port": tcp.sport,
            "dst_port": tcp.dport,
            "protocol": "TCP",
            "flags": tcp.flags  # Captura flags para detecção de SYN Flood
        })
    elif packet.haslayer("UDP"):
        udp = packet["UDP"]
        packet_info.update({
            "src_port": udp.sport,
            "dst_port": udp.dport,
            "protocol": "UDP"
        })

    # Camada ICMP
    if packet.haslayer("ICMP"):
        packet_info.update({
            "icmp_type": packet["ICMP"].type,
            "protocol": "ICMP"
        })

    # Captura ARP (Descoberta de rede)
    if packet.haslayer("ARP"):
        packet_info["arp_op"] = packet["ARP"].op
        packet_info["protocol"] = "ARP"

    # Captura DNS (Consultas de domínio)
    if packet.haslayer("DNS") and packet["DNS"].qd:
        packet_info["dns_query"] = packet["DNS"].qd.qname.decode()
        packet_info["protocol"] = "DNS"

    # Captura HTTP (Requisições web)
    if packet.haslayer("Raw"):
        raw_data = packet["Raw"].load
        if b"HTTP" in raw_data:
            packet_info["protocol"] = "HTTP"
            packet_info["http_data"] = raw_data.decode(errors="ignore")

    # Captura FTP (Transferência de arquivos)
    if packet.haslayer("Raw") and packet.haslayer("TCP"):
        raw_data = packet["Raw"].load
        if b"FTP" in raw_data:
            packet_info["protocol"] = "FTP"
            packet_info["ftp_data"] = raw_data.decode(errors="ignore")

    # Captura SSH (Conexões seguras)
    if packet.haslayer("Raw") and packet.haslayer("TCP"):
        raw_data = packet["Raw"].load
        if b"SSH" in raw_data:
            packet_info["protocol"] = "SSH"
            packet_info["ssh_data"] = raw_data.decode(errors="ignore")

    # Tamanho do pacote
    packet_info["packet_size"] = len(packet)

    # Tempo relativo desde o início da captura
    packet_info["relative_time"] = relative_time

    # Verificação final para pacotes sem protocolo identificado
    if "protocol" not in packet_info:
        packet_info["protocol"] = "Unknown"

    if packet_info:  # Evita adicionar pacotes vazios
        packet_list.append(packet_info)
        detect_attacks(packet_info)  # Detecção de ataques

# Detecção de ataques
def detect_attacks(packet_info):
    global attack_list

    # Port Scanning
    if packet_info.get("protocol") == "TCP":
        src_ip = packet_info["src_ip"]
        dst_port = packet_info["dst_port"]

        if src_ip not in port_scan_tracker:
            port_scan_tracker[src_ip] = {"ports": set(), "start_time": time.time()}

        port_scan_tracker[src_ip]["ports"].add(dst_port)
        if len(port_scan_tracker[src_ip]["ports"]) > 20 and (
                time.time() - port_scan_tracker[src_ip]["start_time"]) < 60:
            attack_list.append({
                "type": "Port Scanning",
                "src_ip": src_ip,
                "timestamp": time.time()
            })
            port_scan_tracker[src_ip] = {"ports": set(), "start_time": time.time()}

    # SYN Flood
    if packet_info.get("protocol") == "TCP" and "S" in packet_info.get("flags", ""):
        src_ip = packet_info["src_ip"]
        syn_flood_tracker[src_ip] = syn_flood_tracker.get(src_ip, 0) + 1
        if syn_flood_tracker[src_ip] > 100:  # 100 SYN/s
            attack_list.append({
                "type": "SYN Flood",
                "src_ip": src_ip,
                "timestamp": time.time()
            })
            syn_flood_tracker[src_ip] = 0

    # ICMP Flood
    if packet_info.get("protocol") == "ICMP":
        src_ip = packet_info["src_ip"]
        icmp_flood_tracker[src_ip] = icmp_flood_tracker.get(src_ip, 0) + 1
        if icmp_flood_tracker[src_ip] > 500:  # 500 ICMP/s
            attack_list.append({
                "type": "ICMP Flood",
                "src_ip": src_ip,
                "timestamp": time.time()
            })
            icmp_flood_tracker[src_ip] = 0


# Função para parar a captura
def stopfilter(packet):  # Aceita um argumento (o pacote capturado)
    global sniffing
    return not sniffing


# Função para capturar pacotes
def capture_packets(interface, filter_expression):
    sniff(
        iface=interface, # Interface de rede escolhida pelo usuário
        prn=process_packet, # Função de processamento de pacotes
        stop_filter=stopfilter, # Função criada para parar a captura
        filter=filter_expression, # Filtro de captura escolhido pelo usuário
    )


# Interface Streamlit
def main():
    global sniffing, packet_list, attack_list

    st.title("Monitor de Rede em Tempo Real")
    st.sidebar.title("Configurações")

    # Configurações de interface e filtros
    interface = st.sidebar.text_input("Interface", value="WiFi")
    filter_expression = st.sidebar.text_input("Filtro de Captura (ex: tcp, udp, icmp)", value="")

    # Iniciar captura em thread separada
    if st.sidebar.button("Iniciar Captura"):
        st.sidebar.write(f"Capturando na interface: {interface}")
        sniffing = True  # Ativa o sinalizador de captura
        capture_thread = threading.Thread(target=capture_packets, args=(interface, filter_expression))
        capture_thread.daemon = True
        capture_thread.start()

    if st.sidebar.button("Parar Captura"):
        sniffing = False
        packet_list.clear()
        attack_list.clear()
        st.sidebar.write("Captura interrompida.")

    # Layout de colunas para organizar a interface
    col1, col2 = st.columns(2, vertical_alignment="bottom")  # Divide a tela em duas colunas
    col3, col4 = st.columns(2, vertical_alignment="bottom")  # Divide a tela em mais duas colunas

    # Espaço reservado para o DataFrame e gráficos no Streamlit
    table_placeholder = col1.empty()
    chart_placeholder = col2.empty()
    attack_placeholder = col3.empty()
    attackChart_placeholder = col4.empty()

    # Mostrar pacotes capturados
    ant = 0
    while True:
        if len(packet_list) - ant > 0:
            with threading.Lock():  # Bloqueia a thread para evitar mudanças simultâneas
                df = pd.DataFrame(packet_list.copy())  # Cria uma cópia segura da lista
                if attack_list:
                    attack_df = pd.DataFrame(attack_list)  # Cria uma cópia segura da lista de ataques

            # Selecionar colunas importantes
            important_columns = ["src_ip", "dst_ip", "protocol",
                                 "packet_size", "relative_time"]
            df = df[important_columns]

            # Renomear colunas para nomes mais claros
            df.rename(columns={
                "src_ip": "IP de Origem",
                "dst_ip": "IP de Destino",
                "protocol": "Protocolo",
                "packet_size": "Tamanho do Pacote",
                "relative_time": "Tempo Relativo"
            }, inplace=True)

            # Converter a coluna de protocolo para string
            df["Protocolo"] = df["Protocolo"].astype(str)

            with table_placeholder.container(height=450):
                st.dataframe(df)  # Aumenta a altura da tabela

            # Gráfico de distribuição por protocolo
            protocol_counts = df["Protocolo"].value_counts().reset_index()
            protocol_counts.columns = ["Protocolo", "Quantidade"]
            with chart_placeholder.container(height=450):
                fig = px.bar(protocol_counts, x="Protocolo", y="Quantidade",
                             title="Distribuição de Pacotes por Protocolo")
                st.plotly_chart(fig)  # Usa a largura total da coluna

            # Mostrar alertas de ataques
            if attack_list:
                with attack_placeholder.container(height=450):
                    st.warning("**Ataques Detectados**")
                    attack_df.rename(columns={
                        "type": "Tipo de Ataque",
                        "src_ip": "IP de Origem",
                        "dst_ip": "IP de Destino",
                        "timestamp": "Tempo Relativo"
                    }, inplace=True)
                    st.dataframe(attack_df)  # Aumenta a altura da tabela de ataques

                # Gráfico de ataques por tipo
                attack_counts = attack_df["Tipo de Ataque"].value_counts().reset_index()
                attack_counts.columns = ["Tipo de Ataque", "Quantidade"]
                fig_attack = px.pie(attack_counts, values="Quantidade", names="Tipo de Ataque",
                                    title="Distribuição de Ataques por Tipo")
                with attackChart_placeholder.container(height=450):
                    st.plotly_chart(fig_attack)  # Usa a largura total da coluna

            ant = len(df)
        time.sleep(1)

if __name__ == "__main__":
    main()