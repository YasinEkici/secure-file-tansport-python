#!/usr/bin/env python3
import subprocess, sys, re

def measure_rtt(host, count=10):
    cmd = ['ping', '-n', str(count), host]
    res = subprocess.run(cmd, capture_output=True, text=True)
    out = res.stdout
    print(out)  # Tam ping çıktısı
    m = re.search(r'Average = (\d+)ms', out)
    if m:
        avg = int(m.group(1))
        print(f"[+] Ortalama RTT: {avg} ms")
        return avg
    else:
        print("RTT bulunamadı.")
        return None

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Kullanım: python measure_latency.py <host> [count]")
        sys.exit(1)
    host = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    measure_rtt(host, count)
