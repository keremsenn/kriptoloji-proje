import base64
import hashlib
from cipher.base import LIBRARY_MODE_AVAILABLE, DES, pad, unpad


class DESCipher:

    @staticmethod
    def _ensure_key(key) -> bytes:
        if isinstance(key, str):
            key_bytes = hashlib.md5(key.encode('utf-8')).digest()[:8]
        else:
            key_bytes = key[:8]
        return key_bytes

    @staticmethod
    def encrypt(text: str, key, use_library: bool = True) -> str:
        key_bytes = DESCipher._ensure_key(key)
        text_bytes = text.encode('utf-8')

        if use_library and LIBRARY_MODE_AVAILABLE:
            return DESCipher._encrypt_library(text_bytes, key_bytes)
        else:
            return DESCipher._encrypt_manual(text_bytes, key_bytes)

    @staticmethod
    def decrypt(ciphertext: str, key, use_library: bool = True) -> str:
        key_bytes = DESCipher._ensure_key(key)

        if use_library and LIBRARY_MODE_AVAILABLE:
            return DESCipher._decrypt_library(ciphertext, key_bytes)
        else:
            return DESCipher._decrypt_manual(ciphertext, key_bytes)

    @staticmethod
    def _encrypt_library(text_bytes: bytes, key: bytes) -> str:
        cipher = DES.new(key, DES.MODE_CBC)
        iv = cipher.iv
        padded_text = pad(text_bytes, 8)

        ciphertext = cipher.encrypt(padded_text)
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    @staticmethod
    def _decrypt_library(ciphertext: str, key: bytes) -> str:
        try:
            data = base64.b64decode(ciphertext)
            iv = data[:8]
            encrypted = data[8:]

            if len(encrypted) % 8 != 0:
                raise ValueError("DES verisi 8 byte'ın katı olmalı!")

            cipher = DES.new(key, DES.MODE_CBC, iv=iv)
            decrypted_raw = cipher.decrypt(encrypted)
            return unpad(decrypted_raw, 8).decode('utf-8')
        except Exception as e:
            print(f"❌ DES Deşifreleme Hatası: {str(e)}")
            raise e

    @staticmethod
    def _encrypt_manual(text_bytes: bytes, key: bytes) -> str:
        result = bytes(b ^ key[i % len(key)] for i, b in enumerate(text_bytes))
        return base64.b64encode(result).decode('utf-8')

    @staticmethod
    def _decrypt_manual(ciphertext: str, key: bytes) -> str:
        data = base64.b64decode(ciphertext)
        result = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        return result.decode('utf-8')