import base64
import hashlib
import os
from cipher.base import LIBRARY_MODE_AVAILABLE, DES, pad, unpad


class DESCipher:
    _IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
           62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
           57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
           61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

    _FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
           38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
           36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
           34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

    @staticmethod
    def _ensure_key(key) -> bytes:
        if isinstance(key, str):
            return hashlib.md5(key.encode('utf-8')).digest()[:8]
        return key[:8]

    # --- ANA API ---
    @staticmethod
    def encrypt(text: str, key, use_library: bool = True) -> str:
        key_bytes = DESCipher._ensure_key(key)
        if use_library and LIBRARY_MODE_AVAILABLE:
            return DESCipher._encrypt_library(text.encode('utf-8'), key_bytes)
        return DESCipher._manual_logic(text, key_bytes, encrypt=True)

    @staticmethod
    def decrypt(ciphertext: str, key, use_library: bool = True) -> str:
        key_bytes = DESCipher._ensure_key(key)
        if use_library and LIBRARY_MODE_AVAILABLE:
            return DESCipher._decrypt_library(ciphertext, key_bytes)
        return DESCipher._manual_logic(ciphertext, key_bytes, encrypt=False)

    @staticmethod
    def _encrypt_library(text_bytes: bytes, key: bytes) -> str:
        cipher = DES.new(key, DES.MODE_CBC)
        iv = cipher.iv
        return base64.b64encode(iv + cipher.encrypt(pad(text_bytes, 8))).decode('utf-8')

    @staticmethod
    def _decrypt_library(ciphertext: str, key: bytes) -> str:
        data = base64.b64decode(ciphertext)
        iv, enc = data[:8], data[8:]
        cipher = DES.new(key, DES.MODE_CBC, iv=iv)
        return unpad(cipher.decrypt(enc), 8).decode('utf-8')

    @classmethod
    def _manual_logic(cls, data_str, key_bytes, encrypt=True):
        subkeys = cls._generate_subkeys(key_bytes)
        if not encrypt:
            subkeys = subkeys[::-1]

        if encrypt:
            iv = os.urandom(8)
            raw_data = pad(data_str.encode('utf-8'), 8)
            result = bytearray()
            prev = iv
            for i in range(0, len(raw_data), 8):
                block = bytes([b ^ p for b, p in zip(raw_data[i:i + 8], prev)])
                enc_block = cls._des_transform(block, subkeys)
                result.extend(enc_block)
                prev = enc_block
            return base64.b64encode(iv + result).decode('utf-8')
        else:
            raw_data = base64.b64decode(data_str)
            iv, encrypted = raw_data[:8], raw_data[8:]
            result = bytearray()
            prev = iv
            for i in range(0, len(encrypted), 8):
                block = encrypted[i:i + 8]
                dec_block = cls._des_transform(block, subkeys)
                result.extend(bytes([b ^ p for b, p in zip(dec_block, prev)]))
                prev = block
            return unpad(result, 8).decode('utf-8')

    @classmethod
    def _des_transform(cls, block, keys):
        val = int.from_bytes(block, byteorder='big')
        bits = bin(val)[2:].zfill(64)

        bits = ''.join(bits[i - 1] for i in cls._IP)
        L, R = int(bits[:32], 2), int(bits[32:], 2)

        for key in keys:
            prev_L = L
            L = R
            f_res = R ^ key
            R = prev_L ^ f_res

        combined = bin(R)[2:].zfill(32) + bin(L)[2:].zfill(32)
        final_bits = ''.join(combined[i - 1] for i in cls._FP)
        return int(final_bits, 2).to_bytes(8, byteorder='big')

    @staticmethod
    def _generate_subkeys(key):
        """Android (generateSubkeys) ile %100 uyumlu anahtar türetimi."""
        md = hashlib.sha1(key)
        h = md.digest()
        # Android tarafındaki '((hash[i % hash.size].toLong() and 0xFF) shl 24) or 0x555555L' mantığı:
        return [((h[i % len(h)] & 0xFF) << 24) | 0x555555 for i in range(16)]