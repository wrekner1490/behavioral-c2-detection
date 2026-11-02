import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import rdpcap, IP, TCP, UDP
import numpy as np

def extract_features(pcap_file, window_size=30.0):
    print(f"[*] Analyzing {pcap_file} with {window_size}s windows...")
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[-] Failed to read pcap: {e}")
        return []

    if not packets:
        print("[-] No packets found.")
        return []
        
    start_time = float(packets[0].time)
    
    # Structure:
    # { flow_key: { "times": [], "sizes": [], "dst_ips": set() } }
    # flow_key = (src_ip, dst_ip, dst_port, window_id)
    flows = {}
    
    for pkt in packets:
        if IP in pkt and (TCP in pkt or UDP in pkt):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
            src_port = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
            
            # Flow Filtering: focus on web/C2 simulated ports
            if dst_port not in [80, 443, 8080] and src_port not in [80, 443, 8080]:
                continue
            
            pkt_time = float(pkt.time)
            pkt_size = len(pkt)
            
            window_id = int((pkt_time - start_time) // window_size)
            flow_key = (src_ip, dst_ip, dst_port, window_id)
            
            if flow_key not in flows:
                flows[flow_key] = {
                    "times": [],
                    "sizes": [],
                    "dst_ips": set()
                }
            
            flows[flow_key]["times"].append(pkt_time)
            flows[flow_key]["sizes"].append(pkt_size)
            flows[flow_key]["dst_ips"].add(dst_ip)
            
    features_list = []
    
    for flow_key, data in flows.items():
        times = sorted(data["times"])
        sizes = data["sizes"]
        dst_ips = data["dst_ips"]
        
        packet_count = len(times)
        if packet_count < 2:
            continue # Need at least 2 packets for intervals
            
        intervals = np.diff(times)
        avg_interval = np.mean(intervals)
        variance = np.var(intervals)
        std_dev_interval = np.std(intervals)
        
        cv = std_dev_interval / avg_interval if avg_interval > 0 else 0
        
        size_std_dev = np.std(sizes)
        session_duration = times[-1] - times[0]
        unique_destinations = len(dst_ips)
        
        src, dst, dport, win_id = flow_key
        
        features_list.append({
            "flow": f"{src} -> {dst}:{dport} (Win {win_id})",
            "avg_interval": avg_interval,
            "variance": variance,
            "std_dev": std_dev_interval,
            "cv": cv,
            "size_std_dev": size_std_dev,
            "packet_count": packet_count,
            "session_duration": session_duration,
            "unique_destinations": unique_destinations
        })
        
    return features_list
