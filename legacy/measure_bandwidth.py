#!/usr/bin/env python3
"""
measure_bandwidth.py — iPerf3 ile bant genişliği ölçer.
Kullanım: python measure_bandwidth.py <server_ip> [duration]
"""

import subprocess, sys, re

def measure_bw(server_ip, duration=10):
    cmd = ['iperf3', '-c', server_ip, '-t', str(duration)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    out = res.stdout
    print(out)
    m = re.search(r'(\d+\.\d+)\s+Mbits/sec', out)
    if m:
        bw = float(m.group(1))
        print(f"[+] Ölçülen bant genişliği: {bw} Mbits/sec")
        return bw
    else:
        print("Bant genişliği bulunamadı.")
        return None

if __name__=='__main__':
    if len(sys.argv)<2:
        print("Kullanım: python measure_bandwidth.py <server_ip> [duration]")
        sys.exit(1)
    srv = sys.argv[1]
    dur = int(sys.argv[2]) if len(sys.argv)>2 else 10
    measure_bw(srv, dur)
