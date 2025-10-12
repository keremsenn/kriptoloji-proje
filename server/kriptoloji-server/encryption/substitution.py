def substitution_encrypt(text: str, key: str) -> str:
    """
    Substitution (yerine koyma) şifreleme algoritması
    """
    if not text or not key:
        return text

    if len(key) != 26:
        raise ValueError("Anahtar 26 karakter uzunluğunda olmalıdır")

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    encrypted_text = ""

    for char in text:
        if char.upper() in alphabet:
            # Karakterin alfabedeki index'ini bul
            index = alphabet.index(char.upper())

            if char.isupper():
                # Büyük harf için şifrele
                encrypted_text += key[index].upper()
            else:
                # Küçük harf için şifrele
                encrypted_text += key[index].lower()
        else:
            # Alfabetik olmayan karakterleri olduğu gibi bırak
            encrypted_text += char

    return encrypted_text


def substitution_decrypt(text: str, key: str) -> str:
    """
    Substitution deşifreleme algoritması
    """
    if not text or not key:
        return text

    if len(key) != 26:
        raise ValueError("Anahtar 26 karakter uzunluğunda olmalıdır")

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    decrypted_text = ""
    key_upper = key.upper()

    for char in text:
        if char.upper() in key_upper:
            # Karakterin anahtardaki index'ini bul
            index = key_upper.index(char.upper())

            if char.isupper():
                # Büyük harf için deşifrele
                decrypted_text += alphabet[index].upper()
            else:
                # Küçük harf için deşifrele
                decrypted_text += alphabet[index].lower()
        else:
            # Alfabetik olmayan karakterleri olduğu gibi bırak
            decrypted_text += char

    return decrypted_text


# Test fonksiyonu
if __name__ == "__main__":
    # Test için örnek anahtar (26 karakter)
    test_key = "ZYXWVUTSRQPONMLKJIHGFEDCBA"  # Ters alfabe

    plain_text = "HELLO WORLD"

    encrypted = substitution_encrypt(plain_text, test_key)
    decrypted = substitution_decrypt(encrypted, test_key)

    print(f"Orijinal: {plain_text}")
    print(f"Şifreli: {encrypted}")
    print(f"Deşifre: {decrypted}")