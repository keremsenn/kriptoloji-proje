from cipher.aes import AESCipher
from cipher.des import DESCipher

class CipherFactory:
    METHODS = {
        'aes': 'AES-128',
        'des': 'DES'
    }

    @staticmethod
    def encrypt(text: str, method: str, key, use_library: bool = True) -> str:
        """Sadece simetrik yöntemlerle (AES/DES) mesaj şifreler."""
        if method == 'aes':
            return AESCipher.encrypt(text, key, use_library)
        elif method == 'des':
            return DESCipher.encrypt(text, key, use_library)
        else:
            raise ValueError(f"Mesajlaşma için desteklenmeyen veya geçersiz yöntem: {method}")

    @staticmethod
    def decrypt(text: str, method: str, key, use_library: bool = True) -> str:
        if method == 'aes':
            return AESCipher.decrypt(text, key, use_library)
        elif method == 'des':
            return DESCipher.decrypt(text, key, use_library)
        else:
            raise ValueError(f"Mesajlaşma için desteklenmeyen veya geçersiz yöntem: {method}")