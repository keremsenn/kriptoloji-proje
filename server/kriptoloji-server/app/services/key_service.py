
import logging
import threading
from typing import Optional, Dict
from cipher.rsa import RSACipher
from config import Config

logger = logging.getLogger(__name__)

class KeyService:
    
    def __init__(self):
        self.rsa_public_key: Optional[str] = None
        self.rsa_private_key: Optional[str] = None
        self.client_keys: Dict[str, Dict[str, str]] = {}
        self.client_rsa_public_keys: Dict[str, str] = {}  # Client RSA public key'leri
        self._lock = threading.Lock()
    
    def initialize(self):
        try:
            self.rsa_public_key, self.rsa_private_key = RSACipher.generate_key_pair()
            logger.info("✅ RSA anahtar çifti oluşturuldu")
            print("✅ RSA anahtar çifti oluşturuldu")
        except Exception as e:
            logger.error(f"❌ RSA anahtar oluşturma hatası: {e}")
            print(f"❌ RSA anahtar oluşturma hatası: {e}")
    
    def get_rsa_public_key(self) -> Optional[str]:
        return self.rsa_public_key
    
    def decrypt_symmetric_key(self, encrypted_key: str) -> Optional[str]:
        if not self.rsa_private_key:
            logger.error("RSA private key bulunamadı")
            return None
        
        try:
            return RSACipher.decrypt(encrypted_key, self.rsa_private_key)
        except Exception as e:
            logger.error(f"Simetrik anahtar deşifreleme hatası: {e}")
            raise
    
    def store_client_key(self, client_id: str, key: str, method: str):
        with self._lock:
            self.client_keys[client_id] = {
                'key': key,
                'method': method
            }
            logger.info(f"✅ İstemci anahtarı saklandı: {client_id} ({method})")
    
    def get_client_key(self, client_id: str) -> Optional[Dict[str, str]]:
        with self._lock:
            return self.client_keys.get(client_id)
    
    def remove_client_key(self, client_id: str):
        with self._lock:
            if client_id in self.client_keys:
                del self.client_keys[client_id]
                logger.info(f"✅ İstemci anahtarı kaldırıldı: {client_id}")
    
    def get_rsa_private_key(self) -> Optional[str]:
        return self.rsa_private_key
    
    def store_client_rsa_public_key(self, client_id: str, public_key: str):
        with self._lock:
            self.client_rsa_public_keys[client_id] = public_key
            logger.info(f"✅ Client RSA public key saklandı: {client_id}")
    
    def get_client_rsa_public_key(self, client_id: str) -> Optional[str]:
        with self._lock:
            return self.client_rsa_public_keys.get(client_id)
    
    def remove_client_rsa_public_key(self, client_id: str):
        with self._lock:
            if client_id in self.client_rsa_public_keys:
                del self.client_rsa_public_keys[client_id]
                logger.info(f"✅ Client RSA public key kaldırıldı: {client_id}")

