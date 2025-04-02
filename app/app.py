import threading
import time
import pandas as pd
import streamlit as st
import plotly.express as px
import socket
from scapy.all import *
from datetime import datetime
from detection import detect_attacks, attack_list

st.set_page_config(layout="wide")

# Obter lista de interfaces de rede disponíveis
interfaces = get_if_list()

# Variáveis globais
packet_list = []
sniffing = True

start_time = None

def format_timestamp(epoch_time):
    return datetime.fromtimestamp(epoch_time).strftime("%Y-%m-%d %H:%M:%S")

# Processamento de pacotes
def process_packet(packet):
    global packet_list, start_time

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

# Função para parar a captura
def stopfilter(packet):  # Aceita um argumento (o pacote capturado)
    global sniffing
    return not sniffing


# Função para capturar pacotes
def capture_packets(interface, filter_expression):
    # Adicionar print para debug
    print(f"Iniciando captura na interface {interface}")
    
    # Modificar o sniff para capturar todo tráfego na subnet
    sniff(
        iface=interface,
        prn=process_packet,
        stop_filter=stopfilter,
        monitor=True,  # Habilita modo promíscuo
        filter=f"{filter_expression}" if filter_expression else "",  # Remove filtro de subnet
    )


# Interface Streamlit
def main():
    global sniffing, packet_list

    st.title("Monitor de Rede em Tempo Real")
    st.sidebar.title("Configurações")

    # Configurações de interface e filtros
    selected_interface = st.sidebar.selectbox("Selecione a interface de rede para análise:", interfaces, key="interface_select")
    filter_expression = st.sidebar.text_input("Filtro de Captura (ex: tcp, udp, icmp)", value="", key="filter_input")

    # Botões de controle
    if st.sidebar.button("Iniciar Captura", key="start_button"):
        st.sidebar.write(f"Capturando na interface: {selected_interface}")
        sniffing = True  # Ativa o sinalizador de captura
        capture_thread = threading.Thread(target=capture_packets, args=(selected_interface, filter_expression))
        capture_thread.daemon = True
        capture_thread.start()

    if st.sidebar.button("Parar Captura", key="stop_button"):
        sniffing = False
        packet_list.clear()
        attack_list.clear()
        st.sidebar.write("Captura interrompida.")

    # Botão de exportação
    #if st.sidebar.button("Exportar Dados CSV", key="export_button"):
    #    csv = df.to_csv(index=False)
    #    st.sidebar.button.download_button(
    #        label="Download CSV",
    #        data=csv,
    #        file_name=f"network_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
    #        mime="text/csv",
    #        key="download_button"
    #    )
            

    # Criar tabs
    tabs = st.tabs(["Pacotes", "Estatísticas", "Visualizações Avançadas", "Alertas"])
    
    # Tab 1: Tabela de pacotes
    with tabs[0]:
        packets_title = st.empty()
        packets_table = st.empty()
    
    # Tab 2: Estatísticas gerais
    with tabs[1]:
        stats_title = st.empty()
        stats_metrics = st.empty()
        
        # Gráficos
        charts_cols = st.columns(2)
        protocol_chart_container = charts_cols[0].empty()
        size_chart_container = charts_cols[1].empty()
    
    # Tab 3: Visualizações avançadas
    with tabs[2]:
        advanced_cols = st.columns(2)
        # Top IPs
        top_ips_title = advanced_cols[0].empty()
        top_ips_chart = advanced_cols[0].empty()
        
        # Série temporal
        traffic_time_title = advanced_cols[1].empty() 
        traffic_time_chart = advanced_cols[1].empty()
        
    # Tab 4: Alertas
    with tabs[3]:
        alerts_warning = st.empty()
        alerts_table = st.empty()
        
        alerts_cols = st.columns(2)
        attack_pie_chart = alerts_cols[0].empty()
        attack_time_chart = alerts_cols[1].empty()
        
        security_title = st.empty()
        security_metrics = st.empty()
    
    # Inicialização
    ant = 0
    export_clicked = False
    
    # Loop de atualização
    while True:
        if len(packet_list) - ant > 0:
            with threading.Lock():
                df = pd.DataFrame(packet_list.copy()) if packet_list else pd.DataFrame()
                attack_list_copy = attack_list.copy()
                if attack_list_copy:
                    attack_df = pd.DataFrame(attack_list_copy)

            if not df.empty:
                timestamp = int(time.time())

                # Preprocessamento dos dados
                important_columns = ["src_ip", "dst_ip", "protocol", "packet_size", "relative_time"]
                df = df[important_columns]
                df.rename(columns={
                    "src_ip": "IP de Origem",
                    "dst_ip": "IP de Destino",
                    "protocol": "Protocolo",
                    "packet_size": "Tamanho do Pacote",
                    "relative_time": "Tempo Relativo"
                }, inplace=True)
                df["Protocolo"] = df["Protocolo"].astype(str)
                
                # Tab 1: Tabela de pacotes
                packets_title.subheader("Pacotes Capturados")
                packets_table.dataframe(df, height=450)
                
                # Tab 2: Estatísticas gerais
                stats_title.subheader("Estatísticas de Rede")
                
                # Métricas em colunas
                col1a, col1b, col1c = stats_metrics.columns(3)
                total_packets = len(df)
                total_bytes = df["Tamanho do Pacote"].sum()
                packets_per_sec = total_packets / (time.time() - start_time) if start_time else 0
                
                col1a.metric("Total de Pacotes", total_packets)
                col1b.metric("Total de Dados", f"{total_bytes/1024:.2f} KB")
                col1c.metric("Pacotes/Segundo", f"{packets_per_sec:.2f}")
                
                # Gráficos
                protocol_counts = df["Protocolo"].value_counts().reset_index()
                protocol_counts.columns = ["Protocolo", "Quantidade"]
                fig_protocol = px.bar(protocol_counts, x="Protocolo", y="Quantidade",
                              title="Distribuição por Protocolo")
                protocol_chart_container.plotly_chart(fig_protocol, use_container_width=True, key=f"protocol_chart_{timestamp}")
                
                fig_size = px.histogram(df, x="Tamanho do Pacote", 
                                    title="Distribuição de Tamanho de Pacotes",
                                    nbins=20)
                size_chart_container.plotly_chart(fig_size, use_container_width=True, key=f"size_chart_{timestamp}")
                
                # Tab 3: Visualizações avançadas
                # Top IPs
                top_src_ips = df["IP de Origem"].value_counts().head(10).reset_index()
                top_src_ips.columns = ["IP de Origem", "Contagem"]
                top_ips_title.subheader("Top 10 IPs Mais Ativos")
                fig_top_ips = px.bar(top_src_ips, x="IP de Origem", y="Contagem", 
                                   title="IPs de Origem Mais Ativos")
                with top_ips_chart:
                    st.plotly_chart(fig_top_ips, use_container_width=True, key=f"top_ips_chart_{timestamp}")
                
                # Série temporal
                if len(df) > 10:
                    traffic_time_title.subheader("Tráfego ao Longo do Tempo")
                    df_time = df.copy()
                    df_time["Tempo"] = pd.to_datetime(df_time["Tempo Relativo"], unit='s')
                    traffic_over_time = df_time.groupby(pd.Grouper(key="Tempo", freq='5s')).size().reset_index()
                    traffic_over_time.columns = ["Tempo", "Pacotes"]
                    fig_time = px.line(traffic_over_time, x="Tempo", y="Pacotes", 
                                    title="Volume de Tráfego por Tempo")
                    traffic_time_chart.plotly_chart(fig_time, use_container_width=True, key=f"traffic_time_chart_{timestamp}")
    
                
                # Tab 4: Alertas de ataques
                if attack_list_copy:
                    alerts_warning.warning("**Ataques Detectados**")
                    attack_df.rename(columns={
                        "type": "Tipo de Ataque",
                        "src_ip": "IP de Origem",
                        "dst_ip": "IP de Destino",
                        "timestamp": "Tempo Relativo"
                    }, inplace=True)
                    
                    alerts_table.dataframe(attack_df)
                    
                    # Gráfico de pizza de ataques
                    attack_counts = attack_df["Tipo de Ataque"].value_counts().reset_index()
                    attack_counts.columns = ["Tipo de Ataque", "Quantidade"]
                    fig_attack = px.pie(attack_counts, values="Quantidade", names="Tipo de Ataque",
                                      title="Distribuição de Ataques por Tipo")
                    attack_pie_chart.plotly_chart(fig_attack, use_container_width=True, key=f"attack_pie_chart_{timestamp}")
                    
                    # Série temporal de ataques
                    attack_df["Tempo"] = pd.to_datetime(attack_df["Tempo Relativo"], unit='s')
                    attack_time = attack_df.groupby([pd.Grouper(key="Tempo", freq='1min'), "Tipo de Ataque"]).size().reset_index()
                    attack_time.columns = ["Tempo", "Tipo de Ataque", "Quantidade"]
                    fig_attack_time = px.line(attack_time, x="Tempo", y="Quantidade", color="Tipo de Ataque",
                                           title="Ataques ao Longo do Tempo")
                    attack_time_chart.plotly_chart(fig_attack_time, use_container_width=True, key=f"attack_time_chart_{timestamp}")
                else:
                    alerts_warning.success("Nenhum ataque detectado até o momento.")
                
                # Estatísticas de segurança
                security_title.subheader("Estatísticas de Segurança")
                col_sec1, col_sec2, col_sec3 = security_metrics.columns(3)
                col_sec1.metric("Total de Ataques", len(attack_list) if attack_list else 0)
                col_sec2.metric("IPs Maliciosos", 
                              len(set([a["src_ip"] for a in attack_list])) if attack_list else 0)
                attack_rate = (len(attack_list) / len(df) * 100) if len(df) > 0 else 0
                col_sec3.metric("Taxa de Ataque", f"{attack_rate:.2f}%")

            ant = len(packet_list)
        time.sleep(1)

if __name__ == "__main__":
    main()