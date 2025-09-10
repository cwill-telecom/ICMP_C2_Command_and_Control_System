

````markdown
# ICMP Command & Control Framework

This project provides a pair of Python scripts that demonstrate **command and control (C2) over ICMP**:

- **Server** (`icmp_command_server.py`)  
  - Sends commands to connected listeners using ICMP Echo Requests.  
  - Receives and processes responses from listeners.  
  - Manages active listener sessions via heartbeats.  

- **Listener** (`icmp_listener.py`)  
  - Runs on a target machine.  
  - Receives ICMP Echo Requests from the server, extracts and executes commands.  
  - Sends command output back via ICMP Echo Replies.  
  - Sends periodic heartbeats to let the server know it is alive.  

> ⚠️ **Disclaimer**: This framework is for **educational and authorized security research only**.  
> Unauthorized use of this tool on networks you do not own or control is illegal.

---

## Features

- **Server**
  - Interactive shell interface
  - `list` command to show active listeners
  - Supports command broadcast to all listeners
  - Handles chunked responses for large outputs

- **Listener**
  - Executes received commands via system shell
  - Sends responses back in multiple chunks if needed
  - Periodic heartbeat system to notify the server of availability

- **Shared Options**
  - Configurable **ICMP ID** and **TTL**
  - Data encoding: `plain`, `base64`, `hex`
  - Optional compression
  - Optional encryption with [Fernet](https://cryptography.io/en/latest/fernet/) symmetric keys
  - Chunked transmission for large payloads

---

## Requirements

- Python **3.7+**
- [Scapy](https://scapy.net/)  
- [cryptography](https://pypi.org/project/cryptography/)

Install dependencies:

```bash
pip install scapy cryptography
````

---

## Usage

### 1. Configure the Listener

Edit the listener script (`icmp_listener.py`) and set your **server IP** at the top:

```python
SERVER_IP = "10.218.248.63"  # Change to your server's IP
```

---

### 2. Start the Server

```bash
python3 icmp_command_server.py -i <INTERFACE> [options]
```

### 3. Start the Listener

```bash
python3 icmp_listener.py -i <INTERFACE> [options]
```

---

## Arguments

Both **server** and **listener** support the following options:

| Option              | Description                                                         | Default      |
| ------------------- | ------------------------------------------------------------------- | ------------ |
| `-i`, `--interface` | Network interface to sniff and send packets on                      | **Required** |
| `--icmp-id`         | ICMP identifier value                                               | `13170`      |
| `--ttl`             | Time-to-live for sent IP packets                                    | `64`         |
| `--encoding`        | Data encoding method (`plain`, `base64`, `hex`)                     | `plain`      |
| `--compress`        | Enable compression before sending                                   | Disabled     |
| `--encrypt`         | Enable encryption (requires `--key`)                                | Disabled     |
| `--key`             | Encryption key for Fernet (must be provided if `--encrypt` is used) | None         |
| `--chunk-size`      | Maximum size (bytes) per packet payload                             | `500`        |

---

## Example Commands

### Run server with base64 encoding and compression

```bash
python3 icmp_command_server.py -i eth0 --encoding base64 --compress
```

### Run listener with encryption enabled

```bash
# Generate a Fernet key
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Run listener with encryption
python3 icmp_listener.py -i wlan0 --encrypt --key <YOUR_KEY>
```

### Send commands from server

Inside the server’s interactive shell:

```
shell> list
Connected listeners:
  - 10.218.248.42

shell> whoami
shell> uname -a
shell> exit
```

---

## Packet Flow Diagram

```
[Server] --(ICMP Echo Request + Command)--> [Listener]
[Listener] --(ICMP Echo Reply + Response)--> [Server]
[Listener] --(ICMP Echo Request + Heartbeat)--> [Server]
```

---

## Security Notes

* **Encryption**: Use Fernet with a shared key between server and listener for confidentiality.
* **Compression**: Reduces packet size, potentially helping with stealth.
* **Encoding**: Use `base64` or `hex` for safer transmission of binary data.
* **Detection**: ICMP-based C2 can be detected by IDS/IPS systems monitoring unusual ICMP payloads.

---

## Disclaimer

This software is intended **solely for research, learning, and authorized security testing**.
The author assumes no liability for misuse. Always ensure you have explicit permission before testing on any network.

---

```
```
