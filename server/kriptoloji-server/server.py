from flask import Flask
from flask_sock import Sock
import json
import logging
from cipher import CipherFactory

# Loglamayı aç
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
sock = Sock(app)

# Varsayılan şifreleme ayarları
DEFAULT_METHOD = 'caesar'
DEFAULT_SHIFT = 3
DEFAULT_VIGENERE_KEY = 'SECRET'
DEFAULT_ROUTE_KEY = 4


@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>Caesar Chat Server</title></head>
    <body>
        <h1>✅ Şifreli Chat WebSocket Sunucusu Çalışıyor</h1>
        <p>WS Endpoint: ws://localhost:5001/ws</p>
        <p>Android'den bağlanmak için: ws://10.0.2.2:5001/ws</p>
        <p><strong>Desteklenen Şifreleme Yöntemleri:</strong></p>
        <ul>
            <li>caesar (shift=3)</li>
            <li>vigenere (key=SECRET)</li>
            <li>routed (key=4)</li>
        </ul>
        <hr>
        <h2>Sunucu Logları:</h2>
        <div id="logs" style="height: 400px; overflow-y: auto; border: 1px solid #ccc; padding: 10px;"></div>
        <script>
            const ws = new WebSocket('ws://localhost:5001/ws');
            const logsDiv = document.getElementById('logs');

            ws.onopen = () => {
                console.log('✅ Test bağlantısı açıldı');
                addLog('✅ Test bağlantısı açıldı');
            };

            ws.onmessage = (event) => {
                console.log('Alındı:', event.data);
                addLog(`📨 Alındı: ${event.data}`);
            };

            ws.onerror = (error) => {
                console.error('❌ Hata:', error);
                addLog(`❌ Hata: ${error}`);
            };

            ws.onclose = () => {
                console.log('❌ Test bağlantısı kapandı');
                addLog('❌ Test bağlantısı kapandı');
            };

            function addLog(msg) {
                const p = document.createElement('p');
                p.textContent = new Date().toLocaleTimeString() + ' - ' + msg;
                logsDiv.appendChild(p);
                logsDiv.scrollTop = logsDiv.scrollHeight;
            }
        </script>
    </body>
    </html>
    '''


@sock.route('/ws')
def websocket(ws):
    client_addr = ws.environ.get('REMOTE_ADDR', 'Unknown')
    logger.info(f"✅ İstemci bağlandı: {client_addr}")
    print(f"\n{'=' * 60}")
    print(f"✅ YENİ BAĞLANTI: {client_addr}")
    print(f"{'=' * 60}\n")

    try:
        while True:
            data = ws.receive()
            if data is None:
                logger.info(f"❌ İstemci bağlantısını kapattı: {client_addr}")
                print(f"\n❌ Bağlantı kapandı: {client_addr}\n")
                break

            print("-" * 60)
            print(f"📥 RAW DATA: {data}")

            # JSON parse et
            try:
                packet = json.loads(data)
                message = packet.get('message', '')
                method = packet.get('method', DEFAULT_METHOD)
                key = packet.get('key', None)

                logger.debug(f"📨 Paket alındı - Method: {method}, Message: {message}")

                # Anahtarları belirle ve dönüştür
                if method == 'caesar':
                    if key is None:
                        key = DEFAULT_SHIFT
                    else:
                        key = int(key) if isinstance(key, str) else key
                elif method == 'vigenere':
                    if key is None:
                        key = DEFAULT_VIGENERE_KEY
                    else:
                        key = str(key)
                elif method == 'routed':
                    if key is None:
                        key = DEFAULT_ROUTE_KEY
                    else:
                        key = int(key) if isinstance(key, str) else key

                print(f"🔐 Şifreleme Yöntemi: {method}")
                print(f"🔑 Anahtar: {key}")
                print(f"📨 Şifreli Mesaj: {message}")

                # Deşifre et
                try:
                    decrypted = CipherFactory.decrypt(message, method, key)
                    print(f"🔓 Çözüldü: {decrypted}")
                except Exception as e:
                    print(f"❌ Deşifreleme Hatası: {e}")
                    logger.error(f"Deşifreleme hatası: {e}", exc_info=True)
                    decrypted = f"[HATA] {str(e)}"

                # İşle
                processed = decrypted + " (sunucuda alındı)"
                print(f"🔄 İşlendi: {processed}")

                # Aynı yönteme göre şifrele
                try:
                    encrypted_response = CipherFactory.encrypt(processed, method, key)
                    print(f"🔐 Şifreli Cevap: {encrypted_response}")
                except Exception as e:
                    print(f"❌ Şifreleme Hatası: {e}")
                    logger.error(f"Şifreleme hatası: {e}", exc_info=True)
                    encrypted_response = processed

                # Cevap paketini oluştur
                response_packet = {
                    "message": encrypted_response,
                    "method": method,
                    "key": str(key) if method != 'caesar' else key
                }
                response = json.dumps(response_packet)

                print(f"📤 Gönderiliyor: {response}")
                ws.send(response)
                print(f"✅ Cevap Gönderildi")

            except json.JSONDecodeError as e:
                print(f"⚠️  JSON Parse Hatası: {e}")
                logger.warning(f"JSON parse başarısız: {data}")
                error_response = {
                    "message": "JSON Parse Hatası",
                    "error": True
                }
                ws.send(json.dumps(error_response))
            except Exception as e:
                logger.error(f"❌ İşlem Hatası: {e}", exc_info=True)
                print(f"❌ İşlem Hatası: {e}")
                error_response = {
                    "message": f"Sunucu Hatası: {str(e)}",
                    "error": True
                }
                ws.send(json.dumps(error_response))

    except Exception as e:
        logger.error(f"❌ Bağlantı Hatası: {e}", exc_info=True)
        print(f"❌ HATA: {e}\n")


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("🚀 Şifreli Chat WebSocket Sunucusu Başlatılıyor...")
    print("=" * 60)
    print("📍 Localhost: ws://localhost:5001/ws")
    print("📍 Android Emulator: ws://10.0.2.2:5001/ws")
    print("🌐 HTTP: http://localhost:5001/")
    print("=" * 60 + "\n")

    app.run(
        host='0.0.0.0',
        port=5001,
        debug=False,
        use_reloader=False
    )