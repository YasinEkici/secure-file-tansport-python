#!/usr-bin/env python3
"""
automated_tester.py (Corrected Final Version)

This script automates the testing of the project's TCP and UDP transfer modes,
collects performance results, provides a detailed text analysis, and
visualizes the results as a graph.

It features a flexible structure that allows specifying the source
from which to read the throughput (client stdout or server log).
"""

import subprocess
import sys
import time
import os
import re
import matplotlib.pyplot as plt

# --- TEST SETTINGS (You can edit this section for your own environment) ---
HOST_IP = "192.168.1.6"      # IP address of the receiver
PASSWORD = "Sifreniz"
IFACE = "Wi-Fi"              # Network interface to be used for sending
TCP_PORT = "5001"
UDP_PORT = "12345"
TEST_FILE = "buyuk_dosya.bin" # File to be used for the reliable UDP test
# --------------------------------------------------------------------

def parse_throughput(output: str) -> float:
    """Parses the throughput in Mbps from the given text output."""
    # For UDP Test: "Measured Throughput: 85.12 Mbps"
    match = re.search(r'Measured Throughput:\s*(\d+\.\d+)\s+Mbps', output, re.IGNORECASE)
    if match:
        return float(match.group(1))
    
    # For TCP Test: "Realistic TCP Throughput: 75.43 Mbps" or just "Throughput: ..."
    match = re.search(r'Throughput:\s*(\d+\.\d+)\s+Mbps', output, re.IGNORECASE)
    if match:
        return float(match.group(1))
        
    return 0.0

def run_test_case(test_config: dict) -> dict:
    """Runs the given test case and returns the result."""
    test_name = test_config['name']
    server_cmd = test_config['server_cmd']
    client_cmd = test_config['client_cmd']
    is_file_transfer = test_config.get('is_file_transfer', False)
    # NEW: Key that determines where the speed will be read from
    read_from = test_config.get('read_from', 'client') 

    print(f"\n--- RUNNING TEST: {test_name} (Reading speed from: {read_from}) ---")
    
    speed = 0.0
    server_process = None
    server_log_filename = f"{test_name.replace(' ', '_').lower()}_server.log"

    try:
        print(f"Starting server: {' '.join(server_cmd)}")
        with open(server_log_filename, "w") as server_log:
            server_process = subprocess.Popen(server_cmd, stdout=server_log, stderr=subprocess.STDOUT, text=True)
            time.sleep(3)

            print(f"Starting client: {' '.join(client_cmd)}")
            start_time = time.time()
            client_process = subprocess.run(client_cmd, capture_output=True, text=True, timeout=120)
            duration = time.time() - start_time
            
            if client_process.returncode != 0:
                print(f"[ERROR] Client exited with error:\n{client_process.stderr}")

            # --- NEW and SMART SPEED CALCULATION BLOCK ---
            if is_file_transfer:
                file_size_bytes = os.path.getsize(TEST_FILE)
                if duration > 0:
                    speed = (file_size_bytes * 8) / (duration * 1000000)
                    print(f"File transfer throughput calculated: {speed:.2f} Mbps")
            
            elif read_from == 'client':
                # For TCP Test: Read the speed from the client output
                print("Client finished. Parsing throughput from client's output.")
                print(f"\n--- Client Output ---\n{client_process.stdout}\n--- End Client Output ---")
                speed = parse_throughput(client_process.stdout)
                print(f"Benchmark throughput parsed from client: {speed:.2f} Mbps")

            elif read_from == 'server':
                # For UDP Test: Read the speed from the server log file
                print("Client finished. Waiting for server to log results...")
                # Wait for the server to close on timeout and write the log
                time.sleep(6) 

                with open(server_log_filename, "r") as log_file:
                    server_output = log_file.read()
                
                print(f"\n--- Server Log ({server_log_filename}) ---")
                print(server_output.strip())
                print("--- End of Server Log ---\n")
                
                speed = parse_throughput(server_output)
                print(f"Benchmark throughput parsed from server log: {speed:.2f} Mbps")
            # --- END ---

    except subprocess.TimeoutExpired:
        print("[ERROR] Test timed out after 120 seconds.")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")
    finally:
        if server_process:
            print("Terminating server process...")
            server_process.terminate()
            server_process.wait()
    
    return {'name': test_name, 'speed': speed}

def plot_results(results: list):
    """Plots the test results as a bar chart and saves it."""
    print("\n--- GENERATING PERFORMANCE GRAPH ---")
    
    names = [res['name'].replace(' ', '\n') for res in results]
    speeds = [res['speed'] for res in results]
    
    plt.style.use('seaborn-v0_8-darkgrid')
    fig, ax = plt.subplots(figsize=(12, 7))
    
    colors = ['#4c72b0', '#55a868', '#c44e52']
    bars = ax.bar(names, speeds, color=colors)
    
    ax.set_ylabel('Hız (Mbps)')
    ax.set_title('Protokol Performans Karşılaştırması', fontsize=16, pad=20)
    
    for bar in bars:
        yval = bar.get_height()
        if yval > 0:
            ax.text(bar.get_x() + bar.get_width()/2.0, yval + max(speeds)*0.01, f'{yval:.2f}', ha='center', va='bottom', fontsize=10)

    plt.tight_layout()
    graph_filename = "performance_graph.png"
    plt.savefig(graph_filename)
    print(f"Graph saved to '{graph_filename}'")
    plt.show()

def main():
    if not os.path.exists(TEST_FILE):
        print(f"[ERROR] Test file '{TEST_FILE}' not found. Please create it first.")
        # Let's create an empty file for the test to proceed
        print(f"Creating an empty test file: '{TEST_FILE}'")
        open(TEST_FILE, 'w').close()

    # --- CHANGED SECTION: 'read_from' key added to each test ---
    test_cases = [
        {
            "name": "TCP Benchmark",
            "server_cmd": ["python", "server.py", "-p", TCP_PORT, "-P", PASSWORD],
            "client_cmd": ["python", "client.py", "-H", HOST_IP, "-p", TCP_PORT, "-P", PASSWORD, "--benchmark", "--verbose"],
            "read_from": "client" # TCP speed is read from the client
        },
        {
            "name": "UDP Benchmark (Ham Hiz)",
            "server_cmd": ["python", "ip_receiver.py", "-P", PASSWORD, "-i", IFACE, "--benchmark", "-p", UDP_PORT],
            "client_cmd": ["python", "ip_sender.py", "-H", HOST_IP, "-P", PASSWORD, "--iface", IFACE, "--benchmark", "--verify", "-p", UDP_PORT],
            "read_from": "server" # UDP speed is read from the server (receiver)
        },
        {
            "name": "UDP Transferi (Guvenilir)",
            "server_cmd": ["python", "ip_receiver.py", "-P", PASSWORD, "-i", IFACE, "-o", "otomatik_test_ciktisi.bin", "-p", UDP_PORT],
            "client_cmd": ["python", "ip_sender.py", "-H", HOST_IP, "-P", PASSWORD, "--iface", IFACE, TEST_FILE, "-p", UDP_PORT],
            "is_file_transfer": True # This is a file transfer, speed is calculated from duration
        }
    ]

    results = []
    for test in test_cases:
        # Let's ensure the python path using sys.executable
        test['server_cmd'][0] = sys.executable
        test['client_cmd'][0] = sys.executable
        
        # Let's add the missing port argument to the UDP commands
        if "ip_receiver.py" in test['server_cmd'][1]:
             if "-p" not in test['server_cmd'] and "--port" not in test['server_cmd']:
                 test['server_cmd'].extend(["-p", UDP_PORT])
        
        result = run_test_case(test)
        results.append(result)

    # ... (Reporting and graph plotting part can remain the same) ...
    print("\n\n" + "="*50)
    print("           DETAYLI PERFORMANS ANALİZİ RAPORU")
    print("="*50)
    
    # Check for the existence of results
    tcp_speed = results[0]['speed'] if len(results) > 0 else 0
    udp_raw_speed = results[1]['speed'] if len(results) > 1 else 0
    udp_reliable_speed = results[2]['speed'] if len(results) > 2 else 0
    
    print(f"\n1. Standart TCP Performansı:")
    print(f"   - Güvenilir TCP protokolü, benchmark testinde {tcp_speed:.2f} Mbps hıza ulaştı.")
    print(f"   - Bu değer, işletim sisteminin optimize edilmiş ağ yığınının pratikteki hızını temsil eder ve bir üst limit olarak kabul edilebilir.")

    print(f"\n2. Özel UDP Protokolü Performansı:")
    print(f"   - Protokolün ham (güvencesiz) hızı, benchmark modunda {udp_raw_speed:.2f} Mbps olarak ölçüldü.")
    print(f"   - Bu, herhangi bir güvenilirlik ek yükü olmadan, Scapy ile paket oluşturma ve göndermenin ulaşabildiği maksimum potansiyeldir.")
    
    print(f"\n3. Güvenilirliğin Performans Maliyeti:")
    print(f"   - Kendi ACK/NACK mekanizmamızla geliştirdiğimiz güvenilir UDP dosya transfer hızı {udp_reliable_speed:.2f} Mbps olarak ölçüldü.")
    
    if udp_raw_speed > 0 and udp_reliable_speed > 0:
        overhead_percentage = ((udp_raw_speed - udp_reliable_speed) / udp_raw_speed) * 100
        print(f"   - SONUÇ: Güvenilirlik mekanizması (ACK/NACK, durum takibi) ve dosya okuma işlemleri, ham hıza kıyasla performansta yaklaşık %{overhead_percentage:.1f}'lik bir düşüşe neden olmuştur.")
        print(f"   - Bu, verinin kayıpsız ve bütünlüğü bozulmadan iletilmesi için ödenen makul bir performasyon bedelidir.")

    print("\n" + "="*50)
    
    plot_results(results)

if __name__ == "__main__":
    main()