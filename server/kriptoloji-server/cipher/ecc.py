import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


class ECCCipher:
    @staticmethod
    def generate_key_pair():
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        clean_pub = public_pem.replace("-----BEGIN PUBLIC KEY-----", "") \
            .replace("-----END PUBLIC KEY-----", "") \
            .replace("\n", "").replace("\r", "").replace(" ", "").strip()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        return clean_pub, private_pem

    @staticmethod
    def derive_shared_key(private_key_pem: str, peer_public_key_base64: str) -> str:
        try:
            # 1. Sunucunun kendi Private Key'ini yükle
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None
            )

            # 2. Android'den gelen saf Base64 Public Key'i PEM formatına geri çevir
            if "BEGIN PUBLIC KEY" not in peer_public_key_base64:
                # Satır uzunluklarına dikkat ederek PEM formatını oluştur
                formatted_pub = f"-----BEGIN PUBLIC KEY-----\n{peer_public_key_base64}\n-----END PUBLIC KEY-----"
            else:
                formatted_pub = peer_public_key_base64

            peer_public_key = serialization.load_pem_public_key(
                formatted_pub.encode('utf-8')
            )

            # 3. ECDH Exchange (Paylaşılan sırrı hesapla)
            shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

            hasher = hashlib.sha256()
            hasher.update(shared_secret)
            derived_key = hasher.digest()[:16]

            return base64.b64encode(derived_key).decode('utf-8')

        except Exception as e:
            print(f"❌ Server ECC Hatası: {str(e)}")
            raise e