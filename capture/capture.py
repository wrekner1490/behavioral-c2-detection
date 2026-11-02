import subprocess
import os
import platform
import time

def capture_traffic(interface, duration, output_file="traffic.pcap"):
    """
    Captures traffic using tshark or tcpdump and saves to a pcap file.
    """
    print(f"[*] Capturing traffic on '{interface}' for {duration} seconds -> {output_file}")
    
    system = platform.system().lower()
    
    try:
        if system == "windows":
            # standard wireshark tshark path on Windows
            tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
            if not os.path.exists(tshark_path):
                tshark_path = "tshark" # Fallback to PATH environment variable
            
            cmd = [tshark_path, "-i", interface, "-a", f"duration:{duration}", "-w", output_file]
        else:
            cmd = ["tcpdump", "-i", interface, "-G", str(duration), "-W", "1", "-w", output_file]
            
        print(f"[*] Command: {' '.join(cmd)}")
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if result.returncode != 0:
            err = result.stderr.decode('utf-8', errors='ignore')
            print(f"[-] Capture error: {err}")
            return False
            
        print(f"[+] Capture complete -> {output_file}")
        return True
    except Exception as e:
        print(f"[-] Failed to execute capture command: {e}")
        return False

# For direct testing
if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="Traffic Capture Wrapper")
    parser.add_argument('--interface', required=True, help="Network interface to listen on")
    parser.add_argument('--duration', type=int, default=30, help="Duration to capture (seconds)")
    parser.add_argument('--output', default="capture.pcap", help="Output pcap file")
    args = parser.parse_args()
    capture_traffic(args.interface, args.duration, args.output)
