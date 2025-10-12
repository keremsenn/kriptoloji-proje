import hashlib


def md5_hash(text: str) -> str:
    """
    MD5 hash fonksiyonu
    """
    if not text:
        return ""

    # Metni MD5 hash'ine dönüştür
    return hashlib.md5(text.encode('utf-8')).hexdigest()


# Test fonksiyonu
if __name__ == "__main__":
    # Test
    test_text = "hello world"
    hashed = md5_hash(test_text)

    print(f"Orijinal: {test_text}")
    print(f"MD5 Hash: {hashed}")
    print(f"Uzunluk: {len(hashed)} karakter")