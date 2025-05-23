# bluetooth_server.py - Version corrigée sans BleakServer
import asyncio
import json
import secrets
import os
import socket
import threading
from bleak import BleakScanner
from rsa_manager import RSAManager

class BluetoothAuthServer:
    def __init__(self, service_name="RSA_Auth_Service"):
        self.service_name = service_name
        self.rsa_manager = RSAManager()
        self.clients = []
        self.running = False
        
        # Pour la simulation, on utilise un socket TCP local
        # En production, vous pouvez utiliser PyBluez pour du vrai Bluetooth
        self.host = 'localhost'
        self.port = 8888
        self.server_socket = None
        
        self.setup_rsa()
    
    def setup_rsa(self):
        """Configure le gestionnaire RSA"""
        keys_dir = os.path.join(os.path.dirname(__file__), '..', 'keys')
        private_key_path = os.path.join(keys_dir, 'private_key.pem')
        public_key_path = os.path.join(keys_dir, 'public_key.pem')
        
        try:
            self.rsa_manager.load_public_key(public_key_path)
            print(" Clé publique chargée avec succès")
        except FileNotFoundError:
            print(" Génération d'une nouvelle paire de clés RSA...")
            self.rsa_manager.generate_keypair()
            self.rsa_manager.save_keys(private_key_path, public_key_path)
            print(f" Clés sauvegardées dans {keys_dir}")
    
    def generate_challenge(self):
        """Génère un challenge aléatoire"""
        return secrets.token_hex(32)  # 256 bits de données aléatoires
    
    async def handle_client(self, client_socket, client_address):
        """Gère une connexion client"""
        print(f"🔗 Nouveau client connecté : {client_address}")
        
        try:
            # Étape 1 : Envoyer la clé publique
            public_key_hex = self.rsa_manager.export_public_key_hex()
            key_message = {
                "type": "public_key",
                "key": public_key_hex
            }
            
            client_socket.send(json.dumps(key_message).encode('utf-8') + b'\n')
            print("📤 Clé publique envoyée au client")
            
            # Étape 2 : Générer et envoyer le challenge
            challenge = self.generate_challenge()
            challenge_message = {
                "type": "challenge",
                "data": challenge
            }
            
            client_socket.send(json.dumps(challenge_message).encode('utf-8') + b'\n')
            print(f" Challenge envoyé : {challenge}")
            
            # Étape 3 : Recevoir la signature
            client_socket.settimeout(30)  # Timeout de 30 secondes
            response_data = client_socket.recv(4096)
            
            if response_data:
                response = json.loads(response_data.decode('utf-8').strip())
                
                if response["type"] == "signature":
                    signature = bytes.fromhex(response["signature"])
                    
                    # Vérifier la signature
                    is_valid = self.rsa_manager.verify_signature(challenge, signature)
                    
                    # Envoyer le résultat
                    result = {
                        "type": "result",
                        "authenticated": is_valid,
                        "message": "Authentification réussie" if is_valid else "Authentification échouée"
                    }
                    
                    client_socket.send(json.dumps(result).encode('utf-8') + b'\n')
                    
                    if is_valid:
                        print("AUTHENTIFICATION RÉUSSIE!")
                    else:
                        print("AUTHENTIFICATION ÉCHOUÉE!")
                    
        except socket.timeout:
            print("Timeout - Le client n'a pas répondu à temps")
        except Exception as e:
            print(f" Erreur avec le client {client_address}: {e}")
        finally:
            client_socket.close()
            print(f" Connexion fermée avec {client_address}")
    
    def client_handler_thread(self, client_socket, client_address):
        """Thread wrapper pour la gestion asynchrone"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.handle_client(client_socket, client_address))
        loop.close()
    
    def start_server(self):
        """Démarre le serveur"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            print(f" Serveur d'authentification RSA démarré")
            print(f" Adresse : {self.host}:{self.port}")
            print(f" Service : {self.service_name}")
            print(f" En attente de connexions...\n")
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    
                    # Gère chaque client dans un thread séparé
                    client_thread = threading.Thread(
                        target=self.client_handler_thread,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.error:
                    if self.running:  # Erreur uniquement si le serveur n'est pas en train de s'arrêter
                        print(" Erreur de socket")
                    break
                    
        except Exception as e:
            print(f" Erreur du serveur : {e}")
        finally:
            self.stop_server()
    
    def stop_server(self):
        """Arrête le serveur"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print(" Serveur arrêté")

# Fonction principale
def main():
    server = BluetoothAuthServer()
    
    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\nArrêt demandé par l'utilisateur")
        server.stop_server()

if __name__ == "__main__":
    main()