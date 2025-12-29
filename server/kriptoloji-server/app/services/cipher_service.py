
import logging
from cipher.factory import CipherFactory
from config import Config

logger = logging.getLogger(__name__)

class CipherService:

    @staticmethod
    def encrypt_message(message: str, method: str, key: str, use_library: bool = True) -> str:
        try:
            return CipherFactory.encrypt(message, method, key, use_library)
        except Exception as e:
            logger.error(f"Şifreleme hatası: {e}")
            raise
    
    @staticmethod
    def decrypt_message(ciphertext: str, method: str, key: str, use_library: bool = True) -> str:
        try:
            return CipherFactory.decrypt(ciphertext, method, key, use_library)
        except Exception as e:
            logger.error(f"Deşifreleme hatası: {e}")
            raise
            
    @staticmethod
    def decrypt_file(ciphertext: str, method: str, key: str, use_library: bool = True) -> bytes:
        try:
            return CipherFactory.decrypt_file(ciphertext, method, key, use_library)
        except Exception as e:
            logger.error(f"Dosya deşifreleme hatası: {e}")
            raise
    
    @staticmethod
    def get_default_key(method: str) -> str:
        if method == 'aes':
            return "default_aes_key_16"
        elif method == 'des':
            return "default_des"
        return ""


