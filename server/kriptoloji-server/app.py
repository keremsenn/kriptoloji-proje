from flask import Flask, request, jsonify
from flask_cors import CORS
from encryption import (
    vigenere_encrypt, vigenere_decrypt,
    substitution_encrypt, substitution_decrypt,
    md5_hash,caesar_encrypt, caesar_decrypt
)

app = Flask(__name__)
CORS(app)  # Android uygulamasından gelen isteklere izin ver


@app.route('/')
def home():
    return jsonify({
        "message": "Kriptoloji API Çalışıyor!",
        "version": "1.0.0",
        "endpoints": {
            "encrypt": "POST /encrypt",
            "decrypt": "POST /decrypt"
        }
    })


@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "JSON verisi bekleniyor"}), 400

        method = data.get('method')
        message = data.get('message', '')
        key = data.get('key', '')

        # Validasyon
        if not method or not message:
            return jsonify({"error": "Method ve message zorunludur"}), 400

        result = ""

        if method == 'vigenere':
            if not key:
                return jsonify({"error": "Vigenère şifreleme için key zorunludur"}), 400
            result = vigenere_encrypt(message, key)

        elif method == 'substitution':
            if not key:
                return jsonify({"error": "Substitution şifreleme için key zorunludur"}), 400
            if len(key) != 26:
                return jsonify({"error": "Substitution anahtarı 26 karakter olmalıdır"}), 400
            result = substitution_encrypt(message, key)

        elif method == 'hash':
            result = md5_hash(message)

        elif method == 'caesar':  # ✅ YENİ
            if not key:
                return jsonify({"error": "Caesar şifreleme için key (shift) zorunludur"}), 400
            try:
                shift = int(key)  # Key olarak sayı bekliyoruz
                result = caesar_encrypt(message, shift)
            except ValueError:
                return jsonify({"error": "Caesar için key bir sayı olmalıdır"}), 400

        else:
            return jsonify({"error": f"Geçersiz method: {method}"}), 400

        return jsonify({
            "success": True,
            "result": result,
            "method": method,
            "original_message": message
        })

    except Exception as e:
        return jsonify({"error": f"Sunucu hatası: {str(e)}"}), 500


@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "JSON verisi bekleniyor"}), 400

        method = data.get('method')
        message = data.get('message', '')
        key = data.get('key', '')

        if not all([method, message, key]):
            return jsonify({"error": "Method, message ve key parametreleri zorunludur"}), 400

        result = ""

        if method == 'vigenere':
            result = vigenere_decrypt(message, key)

        elif method == 'substitution':
            if len(key) != 26:
                return jsonify({"error": "Substitution anahtarı 26 karakter olmalıdır"}), 400
            result = substitution_decrypt(message, key)

        elif method == 'hash':
            result = "Hash işlemi geri alınamaz!"

        elif method == 'caesar':  # ✅ YENİ
            try:
                shift = int(key)  # Key olarak sayı bekliyoruz
                result = caesar_decrypt(message, shift)
            except ValueError:
                return jsonify({"error": "Caesar için key bir sayı olmalıdır"}), 400

        else:
            return jsonify({"error": f"Geçersiz method: {method}"}), 400

        return jsonify({
            "success": True,
            "result": result,
            "method": method,
            "encrypted_message": message
        })

    except Exception as e:
        return jsonify({"error": f"Sunucu hatası: {str(e)}"}), 500




if __name__ == '__main__':
    print("🚀 Kriptoloji Sunucusu Başlatılıyor...")
    print("📱 Android uygulaması için hazır!")
    print("🔗 http://localhost:5001")
    app.run(debug=True, host='0.0.0.0', port=5001)