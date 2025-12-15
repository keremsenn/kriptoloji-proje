
import base64
import json
from typing import Tuple
from cipher.base import LIBRARY_MODE_AVAILABLE, RSA, PKCS1_OAEP, SHA256


class RSACipher:
    @staticmethod
    def generate_key_pair() -> Tuple[str, str]:
        if not LIBRARY_MODE_AVAILABLE:
            raise RuntimeError("RSA için kriptografi kütüphanesi gerekli")
        
        key = RSA.generate(2048)
        private_key_pem = key.export_key().decode('utf-8')
        public_key_pem = key.publickey().export_key().decode('utf-8')
        
        return public_key_pem, private_key_pem

    @staticmethod
    def encrypt(text: str, public_key_pem: str, use_library: bool = True) -> str:
        if not use_library:
            # Manuel (kütüphanesiz) RSA - basitleştirilmiş versiyon
            return RSACipher._encrypt_manual(text, public_key_pem)
        
        if not LIBRARY_MODE_AVAILABLE:
            raise ValueError("RSA şifreleme için kütüphane modu gerekli")
        
        text_bytes = text.encode('utf-8')
        
        # Key formatını kontrol et (PEM veya Base64)
        try:
            # Önce PEM formatı olarak dene
            public_key = RSA.import_key(public_key_pem)
        except (ValueError, IndexError):
            # PEM değilse Base64 olarak dene
            try:
                import base64
                key_bytes = base64.b64decode(public_key_pem)
                public_key = RSA.import_key(key_bytes)
            except Exception:
                # Her ikisi de başarısızsa, key'i direkt kullan (manuel mod için)
                raise ValueError("Geçersiz RSA public key formatı")
        
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        
        chunk_size = 190
        encrypted_chunks = []
        
        for i in range(0, len(text_bytes), chunk_size):
            chunk = text_bytes[i:i+chunk_size]
            encrypted_chunk = cipher.encrypt(chunk)
            encrypted_chunks.append(base64.b64encode(encrypted_chunk).decode('utf-8'))
        
        return json.dumps(encrypted_chunks)

    @staticmethod
    def decrypt(ciphertext: str, key_pem: str, use_library: bool = True) -> str:
        if not use_library:
            # Manuel (kütüphanesiz) RSA - basitleştirilmiş versiyon
            # Manuel modda key_pem aslında public key'dir (server mesajı public key ile şifreler)
            return RSACipher._decrypt_manual(ciphertext, key_pem)
        
        if not LIBRARY_MODE_AVAILABLE:
            raise ValueError("RSA deşifreleme için kütüphane modu gerekli")
        
        # Kütüphaneli modda key_pem private key'dir (gerçek RSA)
        encrypted_chunks = json.loads(ciphertext)
        private_key = RSA.import_key(key_pem)
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        
        decrypted_chunks = []
        for chunk_b64 in encrypted_chunks:
            chunk = base64.b64decode(chunk_b64)
            decrypted_chunk = cipher.decrypt(chunk)
            decrypted_chunks.append(decrypted_chunk)
        
        return b''.join(decrypted_chunks).decode('utf-8')
    
    @staticmethod
    def _encrypt_manual(text: str, public_key_pem: str) -> str:
        import hashlib
        key_bytes_for_hash = public_key_pem.encode('utf-8')
        key_hash = hashlib.md5(key_bytes_for_hash).hexdigest()
        key_bytes = key_hash.encode('utf-8')

        print(f"🔐 Server RSA Manuel Şifreleme - Key hash: {key_hash[:20]}...")
        
        text_bytes = text.encode('utf-8')
        encrypted = bytearray()

        for i in range(len(text_bytes)):
            encrypted.append(text_bytes[i] ^ key_bytes[i % len(key_bytes)])

        encrypted_base64 = base64.b64encode(bytes(encrypted)).decode('utf-8')
        return json.dumps([encrypted_base64])
    
    @staticmethod
    def _decrypt_manual(ciphertext: str, key_pem: str) -> str:
        import hashlib
        key_bytes_for_hash = key_pem.encode('utf-8')
        key_hash = hashlib.md5(key_bytes_for_hash).hexdigest()
        key_bytes = key_hash.encode('utf-8')

        print(f"🔓 Server RSA Manuel Deşifreleme - Key hash: {key_hash[:20]}...")
        
        encrypted_chunks = json.loads(ciphertext)
        encrypted_base64 = encrypted_chunks[0]
        encrypted = base64.b64decode(encrypted_base64)
        
        decrypted = bytearray()

        for i in range(len(encrypted)):
            decrypted.append(encrypted[i] ^ key_bytes[i % len(key_bytes)])
        
        return bytes(decrypted).decode('utf-8')

