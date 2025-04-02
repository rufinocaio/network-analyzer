import time
import json

# Rastreadores para detecção de ataques
port_scan_tracker = {}
syn_flood_tracker = {}
icmp_flood_tracker = {}
udp_flood_tracker = {}
dns_amp_tracker = {}
slowloris_tracker = {}
attack_list = []

def append_attack_list(type, src, dst):
    global attack_list
    attack_list.append({
                "type": type,
                "src_ip": src,
                "dst_ip": dst,
                "timestamp": time.time()
            })
    with open("detected_attacks.json", "w") as f:
        json.dump(attack_list, f, indent=4)
    
def detect_attacks(packet_info):
    global attack_list, port_scan_tracker, syn_flood_tracker, icmp_flood_tracker


    # Port Scanning
    if packet_info.get("protocol") == "TCP":
        src_ip = packet_info["src_ip"]
        dst_port = packet_info["dst_port"]

        if src_ip not in port_scan_tracker:
            port_scan_tracker[src_ip] = {"ports": set(), "start_time": time.time()}

        port_scan_tracker[src_ip]["ports"].add(dst_port)
        if len(port_scan_tracker[src_ip]["ports"]) > 20 and (
                time.time() - port_scan_tracker[src_ip]["start_time"]) < 60:
            append_attack_list("Port Scanning", src_ip, '')
            port_scan_tracker[src_ip] = {"ports": set(), "start_time": time.time()}

    # SYN Flood
    if packet_info.get("protocol") == "TCP" and "S" in packet_info.get("flags", ""):
        src_ip = packet_info["src_ip"]
        syn_flood_tracker[src_ip] = syn_flood_tracker.get(src_ip, 0) + 1
        if syn_flood_tracker[src_ip] > 100:  # 100 SYN/s
            append_attack_list("SYN Flood", src_ip, '')
            syn_flood_tracker[src_ip] = 0

    # ICMP Flood
    if packet_info.get("protocol") == "ICMP":
        src_ip = packet_info["src_ip"]
        icmp_flood_tracker[src_ip] = icmp_flood_tracker.get(src_ip, 0) + 1
        if icmp_flood_tracker[src_ip] > 500:  # 500 ICMP/s
            append_attack_list("ICMP Flood", src_ip, '')
            icmp_flood_tracker[src_ip] = 0

    # UDP Flood
    if packet_info.get("protocol") == "UDP":
        src_ip = packet_info["src_ip"]
        udp_flood_tracker[src_ip] = udp_flood_tracker.get(src_ip, 0) + 1
        if udp_flood_tracker[src_ip] > 200:  # 200 UDP/s
            append_attack_list("UDP Flood", src_ip, '')
            udp_flood_tracker[src_ip] = 0

    # DNS Amplification 
    if packet_info.get("protocol") == "DNS" and packet_info.get("dns_query"):
        src_ip = packet_info["src_ip"]
        if "ANY" in str(packet_info.get("dns_query", "")):
            dns_amp_tracker[src_ip] = dns_amp_tracker.get(src_ip, 0) + 1
            if dns_amp_tracker[src_ip] > 50:
                append_attack_list("DNS Amplification", src_ip, '')
                dns_amp_tracker[src_ip] = 0

    # Slowloris 
    if packet_info.get("protocol") == "TCP" and packet_info.get("packet_size", 0) < 100:
        src_ip = packet_info["src_ip"]
        dst_ip = packet_info["dst_ip"]
        key = f"{src_ip}-{dst_ip}"
        
        if key not in slowloris_tracker:
            slowloris_tracker[key] = {"count": 0, "start_time": time.time()}
        
        slowloris_tracker[key]["count"] += 1
        if (slowloris_tracker[key]["count"] > 50 and 
                (time.time() - slowloris_tracker[key]["start_time"]) > 30):
            append_attack_list("Slowloris", src_ip, dst_ip)
            slowloris_tracker[key] = {"count": 0, "start_time": time.time()}

    return attack_list