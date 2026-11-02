import argparse
import sys
import os
from subprocess import Popen

from capture.capture import capture_traffic
from analysis.extractor import extract_features
from detection.engine import run_detection
from rich.console import Console

console = Console()

def print_demo_instructions():
    console.print("""
[bold green]Behavioral C2 Detection System - Demo Instructions[/bold green]
1. Start the C2 Server in a terminal:
   [cyan]python main.py server[/cyan]
2. Start the Beacon in another terminal (fixed, random, or evasion):
   [cyan]python main.py beacon --mode fixed[/cyan]
3. Start Packet Capture on your active interface (e.g. Wi-Fi or Ethernet):
   [cyan]python main.py capture --interface "Wi-Fi" --duration 30 --output my_traffic.pcap[/cyan]
4. Run the Analyzer on the captured pcap:
   [cyan]python main.py analyze --pcap my_traffic.pcap[/cyan]
""")

def main():
    parser = argparse.ArgumentParser(description="Behavioral C2 Detection System")
    subparsers = parser.add_subparsers(dest="command", help="Module to run")
    
    # Analyze
    parser_analyze = subparsers.add_parser("analyze", help="Analyze a PCAP file and output detection results")
    parser_analyze.add_argument("--pcap", required=True, help="Path to pcap file")
    parser_analyze.add_argument("--window", type=float, default=30.0, help="Time window size (seconds)")
    parser_analyze.add_argument("--debug", action="store_true", help="Enable debug mode for verbose output")
    
    # Server
    parser_server = subparsers.add_parser("server", help="Run the dummy C2 Server")
    
    # Beacon
    parser_beacon = subparsers.add_parser("beacon", help="Run the dummy C2 Beacon")
    parser_beacon.add_argument("--mode", choices=['fixed', 'random', 'evasion'], default='fixed')
    parser_beacon.add_argument("--interval", type=float, default=2.0)
    
    # Capture
    parser_capture = subparsers.add_parser("capture", help="Run packet capture tool")
    parser_capture.add_argument("--interface", required=True, help="Network Interface Name")
    parser_capture.add_argument("--duration", type=int, default=30, help="Duration in seconds")
    parser_capture.add_argument("--output", default="capture.pcap")
    
    # Demo info
    parser_demo = subparsers.add_parser("demo", help="Print demo commands and instructions")

    args = parser.parse_args()
    
    if args.command == "analyze":
        if args.debug:
            console.print("[dim]Debug: Running analyze module with debug enabled[/dim]")
        console.print(f"[*] Analyzing '{args.pcap}' with window={args.window}s...")
        features = extract_features(args.pcap, window_size=args.window)
        run_detection(features, debug=args.debug)
        
    elif args.command == "server":
        print("[*] Launching C2 Server...")
        os.system(f"{sys.executable} server/app.py")
        
    elif args.command == "beacon":
        print("[*] Launching C2 Beacon...")
        os.system(f"{sys.executable} beacon/client.py --mode {args.mode} --interval {args.interval}")
        
    elif args.command == "capture":
        print("[*] Launching Capture Tool...")
        capture_traffic(args.interface, args.duration, args.output)
        
    elif args.command == "demo":
        print_demo_instructions()
        
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
