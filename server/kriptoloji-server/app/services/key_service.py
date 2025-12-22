import logging
import threading
from typing import Optional, Dict
from cipher.rsa import RSACipher
from cipher.ecc import ECCCipher


logger = logging.getLogger(__name__)


class KeyService:

    def __init__(self):
        # --- Sunucu Anahtarları ---
        self.rsa_public_key: Optional[str] = None
        self.rsa_private_key: Optional[str] = None

        self.ecc_public_key: Optional[str] = None
        self.ecc_private_key: Optional[str] = None

        # --- İstemci Verileri (Thread-Safe Saklama) ---
        self.client_keys: Dict[str, Dict[str, str]] = {}
        self.client_rsa_public_keys: Dict[str, str] = {}
        self.client_ecc_public_keys: Dict[str, str] = {}  # Yeni: ECC public key deposu

        self._lock = threading.Lock()

    def initialize(self):
        """Sunucu başladığında anahtar çiftlerini üretir."""
        try:
            # RSA Üretimi
            self.rsa_public_key, self.rsa_private_key = RSACipher.generate_key_pair()

            # ECC Üretimi
            self.ecc_public_key, self.ecc_private_key = ECCCipher.generate_key_pair()

            logger.info("✅ RSA ve ECC anahtar çiftleri başarıyla oluşturuldu")
            print("✅ Sunucu Güvenlik Anahtarları Hazır (RSA & ECC)")
        except Exception as e:
            logger.error(f"❌ Anahtar oluşturma hatası: {e}")
            print(f"❌ Kritik Hata: Anahtarlar oluşturulamadı: {e}")

    # --- RSA Metotları ---
    def get_rsa_public_key(self) -> Optional[str]:
        return self.rsa_public_key

    def get_rsa_private_key(self) -> Optional[str]:
        return self.rsa_private_key

    def decrypt_symmetric_key(self, encrypted_key: str) -> Optional[str]:
        """İstemcinin RSA ile şifreleyip gönderdiği AES/DES anahtarını çözer."""
        if not self.rsa_private_key:
            logger.error("RSA private key bulunamadı")
            return None
        try:
            return RSACipher.decrypt(encrypted_key, self.rsa_private_key)
        except Exception as e:
            logger.error(f"RSA deşifreleme hatası: {e}")
            raise

    # --- ECC (ECDH) Metotları ---
    def get_ecc_public_key(self) -> Optional[str]:
        return self.ecc_public_key

    def get_shared_ecc_key(self, client_public_key_pem: str) -> str:
        """ECDH protokolü ile ortak (paylaşılan) gizli anahtarı hesaplar."""
        if not self.ecc_private_key:
            raise ValueError("Sunucu ECC anahtarı hazır değil")

        return ECCCipher.derive_shared_key(self.ecc_private_key, client_public_key_pem)

    # --- İstemci Yönetimi (Thread-Safe) ---
    def store_client_key(self, client_id: str, key: str, method: str):
        with self._lock:
            self.client_keys[client_id] = {
                'key': key,
                'method': method
            }
            logger.info(f"✅ Simetrik anahtar saklandı: {client_id} ({method})")

    def get_client_key(self, client_id: str) -> Optional[Dict[str, str]]:
        with self._lock:
            return self.client_keys.get(client_id)

    def store_client_rsa_public_key(self, client_id: str, public_key: str):
        with self._lock:
            self.client_rsa_public_keys[client_id] = public_key

    def get_client_rsa_public_key(self, client_id: str) -> Optional[str]:
        with self._lock:
            return self.client_rsa_public_keys.get(client_id)

    def store_client_ecc_public_key(self, client_id: str, public_key: str):
        with self._lock:
            self.client_ecc_public_keys[client_id] = public_key
            logger.info(f"✅ İstemci ECC Public Key saklandı: {client_id}")

    def get_client_ecc_public_key(self, client_id: str) -> Optional[str]:
        with self._lock:
            return self.client_ecc_public_keys.get(client_id)

    def remove_client_data(self, client_id: str):
        with self._lock:
            self.client_keys.pop(client_id, None)
            self.client_rsa_public_keys.pop(client_id, None)
            self.client_ecc_public_keys.pop(client_id, None)
            logger.info(f"🗑️ İstemci verileri temizlendi: {client_id}")