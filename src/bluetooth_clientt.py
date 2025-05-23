import json
import socket
import os
from rsa_manager import RSAManager
import tkinter as tk
from tkinter import scrolledtext

class BluetoothAuthClient:
    def __init__(self):
        self.rsa_manager = RSAManager()
        self.server_public_key_manager = RSAManager()
        self.authenticated = False
        self.host = 'localhost'
        self.port = 8888
        self.root = None
        self.status_text = None
        self.setup_rsa()

    def setup_rsa(self):
        keys_dir = os.path.join(os.path.dirname(__file__), '..', 'keys')
        private_key_path = os.path.join(keys_dir, 'private_key.pem')
        try:
            self.rsa_manager.load_private_key(private_key_path)
            self.update_status("✅ Private key loaded successfully")
        except FileNotFoundError:
            self.update_status("❌ Error: Private key not found!")
            self.update_status("💡 Start the server first to generate keys.")
            exit(1)

    def authenticate_to_server(self):
        try:
            self.update_status(f"🔗 Connecting to {self.host}:{self.port}...")
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.host, self.port))
            client_socket.settimeout(30)

            self.update_status("✅ Connection established")

            key_data = client_socket.recv(4096)
            key_message = json.loads(key_data.decode('utf-8').strip())
            if key_message["type"] == "public_key":
                self.server_public_key_manager.import_public_key_hex(key_message["key"])
                self.update_status("📥 Server public key received")

            challenge_data = client_socket.recv(4096)
            challenge_message = json.loads(challenge_data.decode('utf-8').strip())
            if challenge_message["type"] == "challenge":
                challenge = challenge_message["data"]
                self.update_status(f"📨 Challenge received: {challenge}")

                signature = self.rsa_manager.sign_message(challenge)
                self.update_status("✍️ Challenge signed")

                response = {"type": "signature", "signature": signature.hex()}
                client_socket.send(json.dumps(response).encode('utf-8'))
                self.update_status("📤 Signature sent")

                result_data = client_socket.recv(4096)
                result_message = json.loads(result_data.decode('utf-8').strip())
                if result_message["type"] == "result":
                    self.authenticated = result_message["authenticated"]
                    message = result_message["message"]
                    if self.authenticated:
                        self.update_status(f"✅ {message}")
                        self.update_status("🎉 AUTHENTICATION SUCCESSFUL!")
                    else:
                        self.update_status(f"❌ {message}")
                        self.update_status("💥 AUTHENTICATION FAILED!")

            client_socket.close()
            return self.authenticated
        except socket.timeout:
            self.update_status("⏰ Timeout - Server not responding")
            return False
        except ConnectionRefusedError:
            self.update_status("❌ Cannot connect to server")
            self.update_status("💡 Ensure server is running")
            return False
        except Exception as e:
            self.update_status(f"❌ Authentication error: {e}")
            return False

    def update_status(self, message):
        if self.status_text:  # Check if the UI element exists
            self.status_text.insert(tk.END, message + "\n")
            self.status_text.see(tk.END)
        else:
            print(message)  # Fallback to console output if UI isn't initialized

    def run_with_ui(self):
        self.root = tk.Tk()
        self.root.title("Bluetooth RSA Client")
        self.root.geometry("400x300")
        self.root.configure(bg="#f0f0f0")

        tk.Label(self.root, text="Bluetooth RSA Authentication Client", font=("Arial", 14), bg="#f0f0f0").pack(pady=10)

        self.status_text = scrolledtext.ScrolledText(self.root, width=40, height=15, bg="#ffffff", fg="#333333")
        self.status_text.pack(pady=10)

        tk.Button(self.root, text="Start Authentication", command=self.authenticate_to_server, bg="#4CAF50", fg="white").pack(pady=5)

        self.root.mainloop()

def main():
    client = BluetoothAuthClient()
    client.run_with_ui()

if __name__ == "__main__":
    main()