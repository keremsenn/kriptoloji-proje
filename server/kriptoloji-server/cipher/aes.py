import base64
import hashlib
import os
from cipher.base import LIBRARY_MODE_AVAILABLE, AES, pad, unpad


class AESCipher:
    _s_box = [0] * 256
    _inv_s_box = [0] * 256
    _r_con = [0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
              0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000]

    @classmethod
    def _initialize_manual_aes(cls):
        """Galois Field matematiği ile S-Box ve Ters S-Box üretir."""

        def galois_mult(a, b):
            p = 0
            for _ in range(8):
                if b & 1: p ^= a
                hi = a & 0x80
                a = (a << 1) & 0xFF
                if hi: a ^= 0x1B
                b >>= 1
            return p

        def get_inverse(n):
            if n == 0: return 0
            for i in range(1, 256):
                if galois_mult(n, i) == 1: return i
            return 0

        def rotate_left(val, shift):
            return ((val << shift) & 0xFF) | (val >> (8 - shift))

        for i in range(256):
            inv = get_inverse(i)
            # Affine Transformation
            s = inv ^ rotate_left(inv, 1) ^ rotate_left(inv, 2) ^ \
                rotate_left(inv, 3) ^ rotate_left(inv, 4) ^ 0x63
            cls._s_box[i] = s & 0xFF
            cls._inv_s_box[s & 0xFF] = i

    @staticmethod
    def _ensure_key(key) -> bytes:
        if isinstance(key, str):
            return hashlib.md5(key.encode()).digest()
        return key[:16] if len(key) >= 16 else key.ljust(16, b'\0')

    # --- ANA API METODLARI ---
    @staticmethod
    def encrypt(text: str, key, use_library: bool = True) -> str:
        key_bytes = AESCipher._ensure_key(key)
        if use_library and LIBRARY_MODE_AVAILABLE:
            return AESCipher._encrypt_library(text.encode('utf-8'), key_bytes)

        if AESCipher._s_box[0x63] != 0x7c:
            AESCipher._initialize_manual_aes()
        return AESCipher._encrypt_manual_logic(text, key_bytes)

    @staticmethod
    def decrypt(ciphertext: str, key, use_library: bool = True) -> str:
        key_bytes = AESCipher._ensure_key(key)
        if use_library and LIBRARY_MODE_AVAILABLE:
            return AESCipher._decrypt_library(ciphertext, key_bytes)

        if AESCipher._s_box[0x63] != 0x7c:
            AESCipher._initialize_manual_aes()
        return AESCipher._decrypt_manual_logic(ciphertext, key_bytes)

    # --- KÜTÜPHANELİ METODLAR ---
    @staticmethod
    def _encrypt_library(text_bytes: bytes, key: bytes) -> str:
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        padded_text = pad(text_bytes, 16)
        ciphertext = cipher.encrypt(padded_text)
        return base64.b64encode(iv + ciphertext).decode('utf-8')

    @staticmethod
    def _decrypt_library(ciphertext: str, key: bytes) -> str:
        data = base64.b64decode(ciphertext)
        iv = data[:16]
        encrypted = data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted = unpad(cipher.decrypt(encrypted), 16)
        return decrypted.decode('utf-8')

    # --- MANUEL ÇEKİRDEK OPERASYONLAR ---
    @classmethod
    def _expand_key(cls, key):
        words = []
        for i in range(4):
            words.append((key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3])
        for i in range(4, 44):
            temp = words[i - 1]
            if i % 4 == 0:
                temp = ((temp << 8) & 0xFFFFFFFF) | (temp >> 24)
                temp = (cls._s_box[(temp >> 24) & 0xFF] << 24) | (cls._s_box[(temp >> 16) & 0xFF] << 16) | \
                       (cls._s_box[(temp >> 8) & 0xFF] << 8) | (cls._s_box[temp & 0xFF])
                temp ^= cls._r_con[i // 4]
            words.append(words[i - 4] ^ temp)

        round_keys = []
        for i in range(0, 44, 4):
            # 4x4 matris (sütun öncelikli yapı için uygun r,c dizilimi)
            round_matrix = [[(words[i + j] >> (24 - 8 * r)) & 0xFF for j in range(4)] for r in range(4)]
            round_keys.append(round_matrix)
        return round_keys

    @classmethod
    def _mix_columns(cls, state, inv=False):
        def g_mul(a, b):
            p = 0
            for _ in range(8):
                if b & 1: p ^= a
                hi = a & 0x80
                a = (a << 1) & 0xFF
                if hi: a ^= 0x1B
                b >>= 1
            return p

        for c in range(4):
            col = [state[i][c] for i in range(4)]
            if not inv:
                state[0][c] = g_mul(0x02, col[0]) ^ g_mul(0x03, col[1]) ^ col[2] ^ col[3]
                state[1][c] = col[0] ^ g_mul(0x02, col[1]) ^ g_mul(0x03, col[2]) ^ col[3]
                state[2][c] = col[0] ^ col[1] ^ g_mul(0x02, col[2]) ^ g_mul(0x03, col[3])
                state[3][c] = g_mul(0x03, col[0]) ^ col[1] ^ col[2] ^ g_mul(0x02, col[3])
            else:
                state[0][c] = g_mul(0x0e, col[0]) ^ g_mul(0x0b, col[1]) ^ g_mul(0x0d, col[2]) ^ g_mul(0x09, col[3])
                state[1][c] = g_mul(0x09, col[0]) ^ g_mul(0x0e, col[1]) ^ g_mul(0x0b, col[2]) ^ g_mul(0x0d, col[3])
                state[2][c] = g_mul(0x0d, col[0]) ^ g_mul(0x09, col[1]) ^ g_mul(0x0e, col[2]) ^ g_mul(0x0b, col[3])
                state[3][c] = g_mul(0x0b, col[0]) ^ g_mul(0x0d, col[1]) ^ g_mul(0x09, col[2]) ^ g_mul(0x0e, col[3])

    @classmethod
    def _encrypt_manual_logic(cls, plaintext, key_bytes):
        round_keys = cls._expand_key(key_bytes)
        iv = os.urandom(16)
        pad_len = 16 - (len(plaintext.encode()) % 16)
        data = plaintext.encode() + bytes([pad_len] * pad_len)
        ciphertext = bytearray()
        prev = iv
        for i in range(0, len(data), 16):
            block = bytes([b ^ p for b, p in zip(data[i:i + 16], prev)])
            state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
            for r in range(4):
                for c in range(4): state[r][c] ^= round_keys[0][r][c]
            for j in range(1, 10):
                for r in range(4):
                    for c in range(4): state[r][c] = cls._s_box[state[r][c]]
                state[1] = state[1][1:] + state[1][:1]
                state[2] = state[2][2:] + state[2][:2]
                state[3] = state[3][3:] + state[3][:3]
                cls._mix_columns(state)
                for r in range(4):
                    for c in range(4): state[r][c] ^= round_keys[j][r][c]
            for r in range(4):
                for c in range(4): state[r][c] = cls._s_box[state[r][c]]
            state[1] = state[1][1:] + state[1][:1]
            state[2] = state[2][2:] + state[2][:2]
            state[3] = state[3][3:] + state[3][:3]
            for r in range(4):
                for c in range(4): state[r][c] ^= round_keys[10][r][c]
            out = bytes([state[r][c] for c in range(4) for r in range(4)])
            ciphertext.extend(out)
            prev = out
        return base64.b64encode(iv + ciphertext).decode()

    @classmethod
    def _decrypt_manual_logic(cls, crypto_b64, key_bytes):
        round_keys = cls._expand_key(key_bytes)
        raw = base64.b64decode(crypto_b64)
        iv, data = raw[:16], raw[16:]
        plain = bytearray()
        prev = iv
        for i in range(0, len(data), 16):
            block = data[i:i + 16]
            state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
            for r in range(4):
                for c in range(4): state[r][c] ^= round_keys[10][r][c]
            state[1] = state[1][-1:] + state[1][:-1]
            state[2] = state[2][-2:] + state[2][:-2]
            state[3] = state[3][-3:] + state[3][:-3]
            for r in range(4):
                for c in range(4): state[r][c] = cls._inv_s_box[state[r][c]]
            for j in range(9, 0, -1):
                for r in range(4):
                    for c in range(4): state[r][c] ^= round_keys[j][r][c]
                cls._mix_columns(state, inv=True)
                state[1] = state[1][-1:] + state[1][:-1]
                state[2] = state[2][-2:] + state[2][:-2]
                state[3] = state[3][-3:] + state[3][:-3]
                for r in range(4):
                    for c in range(4): state[r][c] = cls._inv_s_box[state[r][c]]
            for r in range(4):
                for c in range(4): state[r][c] ^= round_keys[0][r][c]
            out = bytes([state[r][c] for c in range(4) for r in range(4)])
            plain.extend(bytes([o ^ p for o, p in zip(out, prev)]))
            prev = block

        pad_len = plain[-1]
        return plain[:-pad_len].decode('utf-8')