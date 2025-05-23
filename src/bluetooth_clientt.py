# bluetooth_client.py - Version corrigée
import json
import socket
import os
from rsa_manager import RSAManager

class BluetoothAuthClient:
    def __init__(self):
        self.rsa_manager = RSAManager()
        self.server_public_key_manager = RSAManager()  # Pour la clé publique du serveur
        self.authenticated = False
        
        # Paramètres de connexion (simulé avec TCP)
        self.host = 'localhost'
        self.port = 8888
        
        self.setup_rsa()
    
    def setup_rsa(self):
        """Configure le gestionnaire RSA"""
        keys_dir = os.path.join(os.path.dirname(__file__), '..', 'keys')
        private_key_path = os.path.join(keys_dir, 'private_key.pem')
        
        try:
            self.rsa_manager.load_private_key(private_key_path)
            print("✅ Clé privée chargée avec succès")
        except FileNotFoundError:
            print("❌ Erreur : Clé privée non trouvée!")
            print("💡 Lancez d'abord le serveur pour générer les clés.")
            exit(1)
    
    def authenticate_to_server(self):
        """S'authentifie auprès du serveur"""
        try:
            print(f"🔗 Connexion au serveur {self.host}:{self.port}...")
            
            # Connexion au serveur
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.host, self.port))
            client_socket.settimeout(30)
            
            print("✅ Connexion établie")
            
            # Étape 1 : Recevoir la clé publique du serveur
            key_data = client_socket.recv(4096)
            key_message = json.loads(key_data.decode('utf-8').strip())
            
            if key_message["type"] == "public_key":
                self.server_public_key_manager.import_public_key_hex(key_message["key"])
                print("📥 Clé publique du serveur reçue")
            
            # Étape 2 : Recevoir le challenge
            challenge_data = client_socket.recv(4096)
            challenge_message = json.loads(challenge_data.decode('utf-8').strip())
            
            if challenge_message["type"] == "challenge":
                challenge = challenge_message["data"]
                print(f"📨 Challenge reçu : {challenge}")
                
                # Étape 3 : Signer le challenge
                signature = self.rsa_manager.sign_message(challenge)
                print("✍️  Challenge signé")
                
                # Étape 4 : Envoyer la signature
                response = {
                    "type": "signature",
                    "signature": signature.hex()
                }
                
                client_socket.send(json.dumps(response).encode('utf-8'))
                print("📤 Signature envoyée")
                
                # Étape 5 : Recevoir le résultat
                result_data = client_socket.recv(4096)
                result_message = json.loads(result_data.decode('utf-8').strip())
                
                if result_message["type"] == "result":
                    self.authenticated = result_message["authenticated"]
                    message = result_message["message"]
                    
                    if self.authenticated:
                        print(f"✅ {message}")
                        print("🎉 AUTHENTIFICATION RÉUSSIE!")
                    else:
                        print(f"❌ {message}")
                        print("💥 AUTHENTIFICATION ÉCHOUÉE!")
            
            client_socket.close()
            return self.authenticated
            
        except socket.timeout:
            print("⏰ Timeout - Le serveur ne répond pas")
            return False
        except ConnectionRefusedError:
            print("❌ Impossible de se connecter au serveur")
            print("💡 Assurez-vous que le serveur est démarré")
            return False
        except Exception as e:
            print(f"❌ Erreur durant l'authentification : {e}")
            return False
    
    def run(self):
        """Lance le processus d'authentification"""
        print("🚀 Démarrage du client d'authentification RSA")
        print("🔍 Recherche du serveur d'authentification...\n")
        
        success = self.authenticate_to_server()
        
        if success:
            print("\n🔐 Dispositif authentifié avec succès auprès du serveur")
        else:
            print("\n🚫 Échec de l'authentification")
        
        return success

# Fonction principale
def main():
    client = BluetoothAuthClient()
    client.run()

if __name__ == "__main__":
    main()