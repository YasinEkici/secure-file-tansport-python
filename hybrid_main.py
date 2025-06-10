#!/usr/bin/env python3
"""
hybrid_main.py - Advanced Secure File Transfer System Controller Script

This script automatically selects the most suitable transfer mode (UDP or TCP)
based on network conditions, or initiates the transfer in a user-specified mode.

- In 'auto' mode, it prefers the fast, low-level UDP for low RTT (<50ms)
  and switches to the reliable TCP for high RTT conditions.
- 'udp' and 'tcp' modes can be used to directly test the respective systems.
"""

import argparse
import subprocess
import sys
import os
import re
import time

def measure_rtt(host: str, count: int = 4) -> int | None:
    """
    Pings the given host and returns the average RTT in milliseconds.
    Compatible with Windows and Linux/macOS.
    """
    print(f"[hybrid] Pinging {host} to determine network conditions...")
    try:
        # Adjust the ping command based on the operating system
        if sys.platform.startswith("win"):
            cmd = ['ping', '-n', str(count), host]
            # On Windows, search for the word 'Average'
            regex = r"Average = (\d+)ms"
        else:
            cmd = ['ping', '-c', str(count), host]
            # On Linux/macOS, search for 'avg' (e.g., rtt min/avg/max/mdev)
            regex = r"avg/max.*\s*=\s*[\d\.]+/([\d\.]+)"

        # Run the command and capture its output
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        # Search for RTT in the output
        match = re.search(regex, res.stdout)
        
        if match:
            rtt = float(match.group(1))
            print(f"[hybrid] Average RTT detected: {rtt:.2f} ms")
            return int(rtt)
        else:
            print("[hybrid] Could not determine RTT from ping output.")
            return None
            
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print("[hybrid] Ping command failed or timed out.")
        return None
    except Exception as e:
        print(f"[hybrid] An unexpected error occurred during ping: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(
        description="Hybrid File Transfer System Controller.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("host", help="Target server IP address.")
    parser.add_argument("input_file", help="Path to the file to be transferred.")
    parser.add_argument("-P", "--password", required=True, help="Shared password for authentication.")
    parser.add_argument("-k", "--key", default="key.key", help="Path to the Fernet encryption key file.")
    parser.add_argument("--port-tcp", type=int, default=5001, help="Port for the TCP server.")
    parser.add_argument("--port-udp", type=int, default=12345, help="Port for the UDP receiver.")
    parser.add_argument(
        "--mode", 
        choices=['auto', 'tcp', 'udp'], 
        default='auto',
        help="Transfer mode:\n"
             "  auto - (Default) Selects best mode based on RTT.\n"
             "  tcp  - Forces reliable TCP transfer.\n"
             "  udp  - Forces low-level UDP transfer."
    )
    parser.add_argument(
        "--iface-udp",
        help="Network interface name (e.g., 'Wi-Fi', 'Ethernet'). Required for UDP tests with a real IP."
    )
    parser.add_argument("--rtt-threshold", type=int, default=50, help="In 'auto' mode, RTT threshold (ms) to prefer TCP over UDP.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging for the transfer scripts.")
    
    args = parser.parse_args()

    # Check if the file to be sent exists
    if not os.path.exists(args.input_file):
        print(f"[hybrid:error] Input file not found: {args.input_file}", file=sys.stderr)
        sys.exit(1)

    # Determine the transfer mode
    transfer_mode = args.mode
    
    if transfer_mode == 'auto':
        rtt = measure_rtt(args.host)
        # If RTT cannot be measured or is higher than the threshold, choose the safe path (TCP)
        if rtt is None or rtt > args.rtt_threshold:
            print(f"[hybrid] RTT is high or unknown. Switching to reliable TCP mode.")
            transfer_mode = 'tcp'
        else:
            print(f"[hybrid] RTT is low. Using fast low-level UDP mode.")
            transfer_mode = 'udp'

    # Call the appropriate script based on the determined mode
    command = [sys.executable] # 'python' or 'python3'
    
    if transfer_mode == 'tcp':
        print("\n[hybrid] --- Starting TCP Transfer ---")
        command.extend([
            'client.py',
            '-H', args.host,
            '-p', str(args.port_tcp),
            '--password', args.password,
            '--key', args.key,
            args.input_file
        ])
        if args.verbose:
            command.append('--verbose')
            
    elif transfer_mode == 'udp':
        print("\n[hybrid] --- Starting Low-Level UDP Transfer ---")
        command.extend([
            'ip_sender.py',
            '-H', args.host,
            '-p', str(args.port_udp),
            '-P', args.password,
            '-k', args.key,
            args.input_file
        ])
        if args.iface_udp:
            command.extend(['--iface', args.iface_udp])
        if args.verbose:
            command.append('--verify') # This is the verbose argument in ip_sender.py

    # Run the command with subprocess
    try:
        start_time = time.time()
        subprocess.run(command, check=True)
        end_time = time.time()
        print(f"\n[hybrid] --- Transfer complete in {end_time - start_time:.2f} seconds ---")
    except FileNotFoundError:
        print(f"[hybrid:error] Script '{command[1]}' not found in the current directory.", file=sys.stderr)
    except subprocess.CalledProcessError:
        print(f"[hybrid:error] The transfer script exited with an error.", file=sys.stderr)
    except Exception as e:
        print(f"[hybrid:error] An unexpected error occurred: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()