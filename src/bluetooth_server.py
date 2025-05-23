import asyncio
import json
import secrets
import os
import socket
import threading
from rsa_manager import RSAManager
import tkinter as tk
from tkinter import scrolledtext

class BluetoothAuthServer:
    def __init__(self, service_name="RSA_Auth_Service"):
        self.service_name = service_name
        self.rsa_manager = RSAManager()
        self.clients = []
        self.running = False
        self.host = 'localhost'
        self.port = 8888
        self.server_socket = None
        self.root = None
        self.status_text = None
        self.setup_rsa()

    def setup_rsa(self):
        keys_dir = os.path.join(os.path.dirname(__file__), '..', 'keys')
        private_key_path = os.path.join(keys_dir, 'private_key.pem')
        public_key_path = os.path.join(keys_dir, 'public_key.pem')
        try:
            self.rsa_manager.load_public_key(public_key_path)
            self.log_message("✅ Clé publique chargée avec succès")
        except FileNotFoundError:
            self.log_message("🔄 Génération d'une nouvelle paire de clés RSA...")
            self.rsa_manager.generate_keypair()
            self.rsa_manager.save_keys(private_key_path, public_key_path)
            self.log_message(f"💾 Clés sauvegardées dans {keys_dir}")

    def generate_challenge(self):
        return secrets.token_hex(32)

    async def handle_client(self, client_socket, client_address):
        self.log_message(f"🔗 Nouveau client connecté : {client_address}")
        try:
            public_key_hex = self.rsa_manager.export_public_key_hex()
            key_message = {"type": "public_key", "key": public_key_hex}
            client_socket.send(json.dumps(key_message).encode('utf-8') + b'\n')
            self.log_message("📤 Clé publique envoyée au client")

            challenge = self.generate_challenge()
            challenge_message = {"type": "challenge", "data": challenge}
            client_socket.send(json.dumps(challenge_message).encode('utf-8') + b'\n')
            self.log_message(f"📨 Challenge envoyé : {challenge}")

            client_socket.settimeout(30)
            response_data = client_socket.recv(4096)
            if response_data:
                response = json.loads(response_data.decode('utf-8').strip())
                if response["type"] == "signature":
                    signature = bytes.fromhex(response["signature"])
                    is_valid = self.rsa_manager.verify_signature(challenge, signature)
                    result = {
                        "type": "result",
                        "authenticated": is_valid,
                        "message": "Authentification réussie" if is_valid else "Authentification échouée"
                    }
                    client_socket.send(json.dumps(result).encode('utf-8') + b'\n')
                    if is_valid:
                        self.log_message("✅ AUTHENTIFICATION RÉUSSIE!")
                    else:
                        self.log_message("❌ AUTHENTIFICATION ÉCHOUÉE!")
        except socket.timeout:
            self.log_message("⏰ Timeout - Le client n'a pas répondu à temps")
        except Exception as e:
            self.log_message(f"❌ Erreur avec le client {client_address}: {e}")
        finally:
            client_socket.close()
            self.log_message(f"🔌 Connexion fermée avec {client_address}")

    def client_handler_thread(self, client_socket, client_address):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.handle_client(client_socket, client_address))
        loop.close()

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            self.log_message(f"🚀 Serveur d'authentification RSA démarré")
            self.log_message(f"📍 Adresse : {self.host}:{self.port}")
            self.log_message(f"🔖 Service : {self.service_name}")
            self.log_message(f"⏳ En attente de connexions...\n")
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.client_handler_thread,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except socket.error:
                    if self.running:
                        self.log_message("❌ Erreur de socket")
                    break
        except Exception as e:
            self.log_message(f"❌ Erreur du serveur : {e}")
        finally:
            self.stop_server()

    def stop_server(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.log_message("🛑 Serveur arrêté")

    def log_message(self, message):
        if self.status_text:
            self.status_text.insert(tk.END, message + "\n")
            self.status_text.see(tk.END)
        else:
            print(message)  # Fallback to console if UI isn't initialized

    def start_server_thread(self):
        server_thread = threading.Thread(target=self.start_server)
        server_thread.daemon = True
        server_thread.start()

    def run_with_ui(self):
        self.root = tk.Tk()
        self.root.title("Bluetooth RSA Server")
        self.root.geometry("400x300")
        self.root.configure(bg="#f0f0f0")

        tk.Label(self.root, text="Bluetooth RSA Authentication Server", font=("Arial", 14), bg="#f0f0f0").pack(pady=10)

        self.status_text = scrolledtext.ScrolledText(self.root, width=40, height=15, bg="#ffffff", fg="#333333")
        self.status_text.pack(pady=10)

        tk.Button(self.root, text="Start Server", command=self.start_server_thread, bg="#4CAF50", fg="white").pack(pady=5)
        tk.Button(self.root, text="Stop Server", command=self.stop_server, bg="#F44336", fg="white").pack(pady=5)

        self.root.mainloop()

def main():
    server = BluetoothAuthServer()
    server.run_with_ui()

if __name__ == "__main__":
    main()