#!/usr/bin/env python3
"""
Buffer Overflow Fuzzing Script
==============================

This script performs fuzzing to identify buffer overflow vulnerabilities
by sending increasingly larger payloads to a target service.

Usage: python3 fuzzing.py <target_ip> <target_port>

Author: CEH Study Guide
Purpose: Educational - Buffer Overflow Testing
"""

import sys
import socket
import time
import argparse

def create_fuzzing_payload(size, char='A'):
    """
    Create a fuzzing payload of specified size
    
    Args:
        size (int): Size of the payload in bytes
        char (str): Character to use for padding
    
    Returns:
        bytes: Fuzzing payload
    """
    return (char * size).encode('latin-1')

def send_payload(target_ip, target_port, payload, timeout=5):
    """
    Send payload to target service
    
    Args:
        target_ip (str): Target IP address
        target_port (int): Target port number
        payload (bytes): Payload to send
        timeout (int): Connection timeout in seconds
    
    Returns:
        bool: True if successful, False if crashed
    """
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(timeout)
        conn.connect((target_ip, target_port))
        conn.send(payload)
        
        # Try to receive response to check if service is still alive
        try:
            response = conn.recv(1024)
        except socket.timeout:
            pass  # Service might not respond, that's ok
        
        conn.close()
        return True
        
    except (socket.error, ConnectionRefusedError) as e:
        print(f"[-] Connection failed: {e}")
        return False
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
        return False

def fuzz_target(target_ip, target_port, initial_size=100, increment=50, max_size=10000):
    """
    Perform fuzzing attack on target service
    
    Args:
        target_ip (str): Target IP address
        target_port (int): Target port number
        initial_size (int): Initial payload size
        increment (int): Size increment for each iteration
        max_size (int): Maximum payload size
    """
    print(f"[+] Starting fuzzing attack on {target_ip}:{target_port}")
    print(f"[+] Initial size: {initial_size}, Increment: {increment}, Max size: {max_size}")
    print("-" * 60)
    
    current_size = initial_size
    
    while current_size <= max_size:
        payload = create_fuzzing_payload(current_size)
        
        print(f"[*] Sending payload of size: {current_size} bytes")
        
        if not send_payload(target_ip, target_port, payload):
            print(f"[!] CRASH DETECTED! Service crashed with payload size: {current_size}")
            print(f"[!] Approximate crash threshold: {current_size - increment} - {current_size} bytes")
            break
        
        print(f"[+] Service responded successfully to {current_size} byte payload")
        current_size += increment
        time.sleep(1)  # Delay between attempts
    
    if current_size > max_size:
        print(f"[*] Fuzzing completed. No crash detected up to {max_size} bytes")

def main():
    parser = argparse.ArgumentParser(
        description="Buffer Overflow Fuzzing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 fuzzing.py 192.168.1.100 9999
  python3 fuzzing.py 127.0.0.1 8888 --initial-size 500 --increment 100
        """
    )
    
    parser.add_argument('target_ip', help='Target IP address')
    parser.add_argument('target_port', type=int, help='Target port number')
    parser.add_argument('--initial-size', type=int, default=100, 
                       help='Initial payload size (default: 100)')
    parser.add_argument('--increment', type=int, default=50,
                       help='Size increment per iteration (default: 50)')
    parser.add_argument('--max-size', type=int, default=10000,
                       help='Maximum payload size (default: 10000)')
    
    args = parser.parse_args()
    
    try:
        fuzz_target(args.target_ip, args.target_port, 
                   args.initial_size, args.increment, args.max_size)
    except KeyboardInterrupt:
        print("\n[!] Fuzzing interrupted by user")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()