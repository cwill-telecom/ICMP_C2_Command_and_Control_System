# ICMP C2 (Command and Control) Toolkit

A stealthy ICMP-based command and control system that allows remote command execution through ICMP (ping) packets, bypassing traditional network monitoring that often overlooks ICMP traffic.

## Overview

This toolkit consists of two components:

1. **`icmp_command_server.py`** - The C2 server that sends commands to the target
2. **`icmp_listener.py`** - The implant/agent that executes commands and returns results

Both tools use ICMP Echo Request/Reply packets to communicate, making the traffic appear as normal ping activity.

## Features

- **Stealthy Communication**: Uses ICMP packets that blend with normal network traffic
- **Multiple Encoding Options**: Plain text, Base64, and Hex encoding support
- **Compression**: Optional zlib compression to reduce packet size
- **Encryption**: Fernet encryption for secure communications (requires key)
- **Chunking**: Splits large commands/responses across multiple packets
- **Cross-Platform**: Works on any system with Python and scapy

## Requirements

- Python 3.x
- scapy: `pip install scapy`
- cryptography (for encryption): `pip install cryptography`

## Usage

### On the Target Machine (Listener)

```bash
python3 icmp_listener.py -i [INTERFACE] [OPTIONS]
```

### On the C2 Server (Command Server)

```bash
python3 icmp_command_server.py -i [INTERFACE] -d [TARGET_IP] [OPTIONS]
```

## Options

### Common Options (both scripts):
- `-i, --interface`: Network interface to use (required)
- `--icmp-id`: ICMP ID to use for communication (default: 13170)
- `--ttl`: IP TTL value (default: 64)
- `--encoding`: Data encoding method: plain, base64, or hex (default: plain)
- `--compress`: Enable compression
- `--encrypt`: Enable encryption (requires --key)
- `--key`: Encryption key (required if --encrypt is used)
- `--chunk-size`: Maximum chunk size in bytes (default: 500)

### Command Server Specific:
- `-d, --destination_ip`: Target IP address (required)
- `--timeout`: Response timeout in seconds (default: 5)

### Listener Specific:
- `--timeout`: Response timeout in seconds (default: 2)

## Examples

### Basic Usage
```bash
# On target machine
python3 icmp_listener.py -i eth0

# On C2 server
python3 icmp_command_server.py -i eth0 -d 192.168.1.100
```

### With Encryption
```bash
# Generate a key (requires cryptography)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# On target machine
python3 icmp_listener.py -i eth0 --encrypt --key "GENERATED_KEY"

# On C2 server
python3 icmp_command_server.py -i eth0 -d 192.168.1.100 --encrypt --key "GENERATED_KEY"
```

### With Encoding and Compression
```bash
# On target machine
python3 icmp_listener.py -i eth0 --encoding base64 --compress

# On C2 server
python3 icmp_command_server.py -i eth0 -d 192.168.1.100 --encoding base64 --compress
```

## How It Works

1. The command server sends commands embedded in ICMP Echo Request packets
2. The listener detects these packets, extracts and executes the commands
3. The listener sends back command output in ICMP Echo Reply packets
4. Both components can encode, compress, and encrypt the data for stealth

## Security Considerations

- This tool is for educational and authorized testing purposes only
- ICMP traffic may be blocked by firewalls in secure environments
- Using encryption is recommended for operational security
- The default ICMP ID (13170) can be changed to avoid detection

## Limitations

- Requires root/administrator privileges to send/receive raw packets
- Performance is limited by the IC packet size and network conditions
- Not suitable for large file transfers due to packet size constraints

## Disclaimer

This tool is provided for educational purposes only. Use only on systems you own or have explicit permission to test. The authors are not responsible for any misuse or damage caused by this tool.
