#!/usr/bin/env python3
"""
Simple concurrent TCP port scanner for your own router.
Usage:
    python scanner.py            # auto-detects router and scans common ports
    python scanner.py 192.168.1.1    # scan that IP (common ports)
    python scanner.py 192.168.1.1 1-1024    # scan range 1..1024
"""

import socket
import subprocess
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

# ------------ utils ------------
def get_default_gateway():
    """Return default gateway IPv4 as string, or None if not found."""
    try:
        if os.name == "nt":  # Windows
            out = subprocess.check_output(["ipconfig"], encoding="utf-8", errors="ignore")
            for line in out.splitlines():
                if "Default Gateway" in line and ":" in line:
                    candidate = line.split(":", 1)[1].strip()
                    if candidate:
                        return candidate
        else:  # Linux / macOS
            out = subprocess.check_output(["ip", "route"], encoding="utf-8", errors="ignore")
            for line in out.splitlines():
                if line.startswith("default"):
                    parts = line.split()
                    # default via <gateway> ...
                    if "via" in parts:
                        return parts[parts.index("via") + 1]
                    # some systems show: default <gateway> dev ...
                    return parts[2]
    except Exception:
        return None

# ------------ scanner core ------------
def scan_port(ip, port, timeout=0.6):
    """Try connect to (ip, port). Return (port, is_open, banner_or_none)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        # try small banner read (non-blocking-ish)
        s.settimeout(0.3)
        try:
            banner = s.recv(1024)
            banner = banner.decode(errors="ignore").strip()
            if banner == "":
                banner = None
        except Exception:
            banner = None
        s.close()
        return port, True, banner
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return port, False, None

# ------------ convenience ------------
COMMON_PORTS = [
    20,21,22,23,25,53,67,68,69,80,110,123,137,138,139,143,161,162,179,389,443,445,465,
    500,514,587,631,636,873,993,995,1080,1433,1521,1701,1723,3306,3389,5060,5061,5432,5900,8080
]

def parse_port_arg(arg):
    """Accept '1-1024' or '22,80,443' or single port.""" 
    if "-" in arg:
        start, end = arg.split("-",1)
        return list(range(int(start), int(end)+1))
    elif "," in arg:
        return [int(x.strip()) for x in arg.split(",") if x.strip()]
    else:
        return [int(arg)]

# ------------ CLI ------------
def main():
    if len(sys.argv) == 1:
        ip = get_default_gateway() or input("Could not auto-detect gateway. Enter router IP: ").strip()
        ports = COMMON_PORTS
    elif len(sys.argv) == 2:
        ip = sys.argv[1]
        ports = COMMON_PORTS
    else:
        ip = sys.argv[1]
        ports = parse_port_arg(sys.argv[2])

    print(f"Scanning {ip} ({len(ports)} ports)... (Press Ctrl+C to stop)")

    open_ports = []
    # tune max_workers based on how many ports you're scanning
    max_workers = min(200, max(20, len(ports)//2))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(scan_port, ip, p): p for p in ports}
        try:
            for fut in as_completed(futures):
                port, is_open, banner = fut.result()
                if is_open:
                    open_ports.append((port, banner))
                    if banner:
                        print(f"[OPEN] {port:5d}  banner: {banner}")
                    else:
                        print(f"[OPEN] {port:5d}")
        except KeyboardInterrupt:
            print("\nScan interrupted by user.")
    if open_ports:
        print("\nSummary of open ports:")
        for p, b in sorted(open_ports):
            if b:
                print(f" - {p}: banner='{b}'")
            else:
                print(f" - {p}")
    else:
        print("\nNo open TCP ports found in scanned range/list (or firewall filtered them).")

if __name__ == "__main__":
    main()