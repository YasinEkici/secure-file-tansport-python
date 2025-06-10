#!/usr/bin/env python3
"""
ip_receiver.py 

Benchmark mode and normal file transfer mode have been separated within the
main function, allowing the script to run in two different paths.
"""

import argparse
import struct
import sys
import hashlib
import os
import socket
import threading
import time
from collections import defaultdict

# UDP protocol number in IP header
UDP_PROTO = 17

from scapy.all import sniff, IP, UDP, Raw, conf, get_if_list
from cryptography.fernet import Fernet

### HELPER FUNCTIONS ###

def detect_loopback_iface():
    for ifc in get_if_list():
        n = ifc.lower()
        if 'loopback' in n or n.startswith('lo'):
            return ifc
    return conf.iface

def load_key(path):
    if not os.path.exists(path):
        print(f"[error] Key file '{path}' not found", file=sys.stderr)
        sys.exit(1)
    return open(path,'rb').read().strip()

def sha256_bytes(data: bytes) -> bytes:
    h = hashlib.sha256(); h.update(data); return h.digest()


def run_benchmark_receiver(args):
    """
    Receives benchmark data using a simple socket and calculates received bytes.
    This does NOT use Scapy.
    """
    print("[benchmark] Receiver started in benchmark mode.")
    
    total_received = 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # --- NEWLY ADDED LINES ---
    # Add a timeout so the receiver doesn't wait forever after the sender stops.
    # The receiver will stop itself 5 seconds after the transmission ends.
    sock.settimeout(5.0) 
    # --- END ---

    start_time = 0

    try:
        sock.bind(('', args.port))
        print(f"[benchmark] Listening for benchmark data on port {args.port}...")

        # Start the timer after receiving the first packet
        data, addr = sock.recvfrom(args.mtu + 200)
        total_received += len(data)
        start_time = time.time()
        
        while True:
            data, addr = sock.recvfrom(args.mtu + 200)
            if data == b"BENCHMARK_FIN":
                print("\n[benchmark] FIN packet received. Stopping benchmark.")
                break
            total_received += len(data)

    # --- CHANGED BLOCK ---
    except socket.timeout:
        print("[benchmark] Socket timed out. Assuming transfer is complete.")
    except Exception as e:
        print(f"[benchmark:error] An error occurred: {e}")
    # --- END ---
    finally:
        sock.close()

    if start_time == 0:
        print("[benchmark:error] No data was received.")
        return

    duration = time.time() - start_time
    if duration > 0.01:
        throughput_mbps = (total_received * 8) / (duration * 1000 * 1000)
        print("-" * 30)
        print(f"[benchmark] Test Complete!")
        print(f"[benchmark] Received {total_received / 1024 / 1024:.2f} MB in {duration:.2f} seconds.")
        # --- CHANGED LINE: Standardizing the format to make parsing easier ---
        print(f"[benchmark] Measured Throughput: {throughput_mbps:.2f} Mbps")
        print("-" * 30)


### MAIN FUNCTION ###

def main():
    # 1. Define Arguments
    p = argparse.ArgumentParser("UDP receiver + manual-frag reassembly + NACK/ACK + HASH‐handshake")
    p.add_argument('-p','--port', type=int, default=12345, help="Data UDP port")
    p.add_argument('-k','--key', default='key.key', help="Fernet key file")
    p.add_argument('-P','--password',required=True, help="Shared password")
    p.add_argument('-i','--iface', help="Scapy interface")
    p.add_argument('-o','--output', default='received_udp.txt', help="Output filename")
    p.add_argument('--verify', action='store_true', help="Verbose logging")
    p.add_argument('--benchmark', action='store_true', help="Run in bandwidth benchmark mode.")
    # The MTU argument might also be needed for the benchmark function
    p.add_argument('--mtu', type=int, default=1500, help="MTU size for buffer calculation.")
    args = p.parse_args()

    # 2. Benchmark Mode Check
    # If the --benchmark argument is given, run the simple benchmark receiver and exit the program.
    if args.benchmark:
        run_benchmark_receiver(args)
        sys.exit(0)

    # 3. Normal File Transfer Mode (This part runs if not in benchmark mode)
    # This section contains the core logic for reliable file transfer.
    iface = args.iface
    if not iface:
        print("[error] An interface must be specified for sniffing in file transfer mode.", file=sys.stderr)
        sys.exit(1)

    if args.verify:
        print(f"[info] Using interface {iface}")

    key = load_key(args.key)
    fernet = Fernet(key)
    pwd = args.password.encode()

    frag_buf = defaultdict(lambda: {'parts':{}, 'expected_size':None})
    chunk_buf = {}
    received_hash = None
    expected_tot = None
    sender_ip = None
    
    finished_event = threading.Event()
    lock = threading.Lock()

    ack_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def try_reassemble(key4):
        info = frag_buf[key4]
        exp = info['expected_size']
        if exp is None: return None
        got = sum(len(b) for b in info['parts'].values())
        if got != exp: return None
        data = b''.join(info['parts'][off] for off in sorted(info['parts']))
        del frag_buf[key4]
        return data

    def packet_handler(pkt):
        nonlocal received_hash, expected_tot, sender_ip

        if IP not in pkt or pkt[IP].proto != 17:
            return
    
        ip = pkt[IP]
        ip_payload = bytes(ip.payload)
        key4 = (ip.src, ip.dst, ip.id, ip.proto)
        offset = ip.frag * 8
        MF = bool(ip.flags & 0x1)

        frag_buf[key4]['parts'][offset] = ip_payload
        if not MF:
            frag_buf[key4]['expected_size'] = offset + len(ip_payload)

        reassembled_ip_payload = try_reassemble(key4)
        if reassembled_ip_payload is None:
            return

        try:
            udp_pkt = UDP(reassembled_ip_payload)
        except Exception:
            if args.verify: print(f"[warn] Failed to parse reassembled data as UDP for IP.id={ip.id}")
            return
            
        if udp_pkt.dport != args.port:
            return
            
        data = bytes(udp_pkt.payload)

        with lock:
            if sender_ip is None:
                sender_ip = ip.src

            if received_hash is None:
                hash_prefix = pwd + b"HASH"
                if data.startswith(hash_prefix) and len(data) >= len(hash_prefix) + 32:
                    received_hash = data[len(hash_prefix) : len(hash_prefix) + 32]
                    if args.verify: print(f"[info] Received SHA256 hash: {received_hash.hex()}")
                    ack = pwd + b"HASH_ACK"
                    dest = sender_ip if sender_ip and '.' in sender_ip else '127.0.0.1'
                    ack_sock.sendto(ack, (dest, args.port+1))
                    if args.verify: print(f"[info] Sent HASH_ACK to {dest}:{args.port+1}")
                return

            data_prefix = pwd + b"DATA"
            if not data.startswith(data_prefix):
                if args.verify:
                    print(f"[debug:warn] Ignoring a packet without DATA tag.")
                return

            try:
                header_offset = len(data_prefix)
                hdr = data[header_offset : header_offset + 8]
                idx, tot = struct.unpack('!II', hdr)
                ct = data[header_offset + 8:]
            except struct.error:
                if args.verify: print(f"[warn] Received malformed data chunk. IP.id={ip.id}")
                return

            if expected_tot is None:
                expected_tot = tot
                if args.verify: print(f"[info] Expecting {tot} chunks total.")

            if tot != expected_tot or idx in chunk_buf:
                return

            chunk_buf[idx] = ct
            if args.verify: print(f"[info] Got chunk {idx+1}/{tot} (from IP.id={ip.id})")

            if len(chunk_buf) == expected_tot:
                full_ct = b''.join(chunk_buf[i] for i in range(expected_tot))
                try:
                    pt = fernet.decrypt(full_ct)
                except Exception as e:
                    print(f"[error] Decrypt failed: {e}", file=sys.stderr)
                    finished_event.set()
                    return

                local_h = sha256_bytes(pt)
                if args.verify: print(f"[info] Computed SHA256: {local_h.hex()}")
                if local_h != received_hash:
                    print("[error] Integrity check failed!", file=sys.stderr)
                else:
                    with open(args.output,'wb') as f: f.write(pt)
                    print(f"[info] Integrity OK -> wrote '{args.output}'")
                    ack = pwd + b"ACK"
                    dest = sender_ip if sender_ip and '.' in sender_ip else '127.0.0.1'
                    for _ in range(3):
                        ack_sock.sendto(ack, (dest, args.port+1))
                        time.sleep(0.01)
                    if args.verify: print(f"[info] Sent final ACK to {dest}:{args.port+1}")
                
                finished_event.set()

    sniffer_thread = threading.Thread(
        target=lambda: sniff(
            iface=iface,
            prn=packet_handler,
            store=0,
            lfilter=lambda p: IP in p,
            stop_filter=lambda p: finished_event.is_set()
        ),
        daemon=True
    )
    
    print("[info] Receiver started, listening for IP packets...")
    sniffer_thread.start()

    while not finished_event.is_set():
        time.sleep(2)
        with lock:
            if not received_hash or finished_event.is_set():
                continue

            if expected_tot:
                missing_indices = [i for i in range(expected_tot) if i not in chunk_buf]
                if not missing_indices:
                    continue
                if expected_tot > 100000:
                    print(f"[debug:error] Beklenen chunk sayısı ({expected_tot}) hala çok yüksek. Transfer durduruluyor.")
                    finished_event.set()
                    continue
                MAX_NACK_INDICES = 100
                nack_batch = missing_indices[:MAX_NACK_INDICES]
                missing_str_list = [str(i) for i in nack_batch]
                if missing_str_list:
                    nack_payload = ",".join(missing_str_list).encode()
                    nack = pwd + b"NACK" + nack_payload
                    if len(nack) > 1400:
                        # print(f"[debug:warn] NACK packet is larger than expected, not sending. Size: {len(nack)}")
                        continue
                    dest = sender_ip if sender_ip and '.' in sender_ip else '127.0.0.1'
                    ack_sock.sendto(nack, (dest, args.port+1))
                    if args.verify:
                        print(f"[info] Sent NACK for {len(nack_batch)} chunks (first {MAX_NACK_INDICES} missing): {','.join(missing_str_list)}")
    
    sniffer_thread.join(timeout=1.0)
    ack_sock.close()
    print("[info] Receiver finished.")


if __name__=="__main__":
    main()