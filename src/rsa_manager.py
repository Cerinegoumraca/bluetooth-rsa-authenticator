# rsa_manager.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os

class RSAManager:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
    
    def generate_keypair(self):
        """Génère une paire de clés RSA"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size
        )
        self.public_key = self.private_key.public_key()
        return self.private_key, self.public_key
    
    def save_keys(self, private_path, public_path):
        """Sauvegarde les clés sur disque"""
        os.makedirs(os.path.dirname(private_path), exist_ok=True)
        
        # Clé privée
        with open(private_path, 'wb') as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Clé publique
        with open(public_path, 'wb') as f:
            f.write(self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    
    def load_private_key(self, path):
        """Charge la clé privée depuis un fichier"""
        with open(path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(), password=None
            )
        self.public_key = self.private_key.public_key()
    
    def load_public_key(self, path):
        """Charge la clé publique depuis un fichier"""
        with open(path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(f.read())
    
    def sign_message(self, message):
        """Signe un message avec la clé privée"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify_signature(self, message, signature):
        """Vérifie une signature avec la clé publique"""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def export_public_key_hex(self):
        """Exporte la clé publique en format hex pour transmission"""
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_bytes.hex()
    
    def import_public_key_hex(self, hex_key):
        """Importe une clé publique depuis un format hex"""
        public_bytes = bytes.fromhex(hex_key)
        self.public_key = serialization.load_pem_public_key(public_bytes)