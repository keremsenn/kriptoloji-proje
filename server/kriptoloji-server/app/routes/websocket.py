import json
import logging
import threading
import traceback
from flask_sock import Sock
from app.models.message import MessagePacket
from app.services.cipher_service import CipherService
from app.services.key_service import KeyService
from config import Config

logger = logging.getLogger(__name__)


def register_socket_routes(sock: Sock, key_service: KeyService):
    @sock.route('/ws')
    def websocket(ws):
        client_addr = ws.environ.get('REMOTE_ADDR', 'Unknown')
        client_id = f"{client_addr}_{threading.current_thread().ident}"

        logger.info(f"✅ İstemci bağlandı: {client_addr}")
        print(f"\n{'=' * 60}")
        print(f"✅ YENİ BAĞLANTI: {client_addr} (ID: {client_id})")
        print(f"{'=' * 60}\n")

        try:
            while True:
                data = ws.receive()
                if data is None:
                    logger.info(f"❌ İstemci bağlantısını kapattı: {client_addr}")
                    print(f"\n❌ Bağlantı kapandı: {client_addr}\n")
                    key_service.remove_client_data(client_id)
                    break

                try:
                    packet = json.loads(data)
                    packet_type = packet.get('type')

                    # 1. BAĞLANTI KURULUMU VE YÖNTEM SEÇİMİ
                    if packet_type == 'setup_connection':
                        preferred = packet.get('preferred_method', 'rsa')
                        logger.info(f"🔄 Bağlantı kurulumu başlatıldı: {preferred}")

                        if preferred == 'ecc':
                            # ECC seçildiyse sunucu ECC public key'ini gönderir
                            ecc_pub = key_service.get_ecc_public_key()
                            ws.send(json.dumps({
                                "type": "ecc_public_key",
                                "public_key": ecc_pub
                            }))
                            print("📤 ECC Public Key gönderildi")
                        else:
                            # RSA seçildiyse sunucu RSA public key'ini gönderir
                            rsa_pub = key_service.get_rsa_public_key()
                            ws.send(json.dumps({
                                "type": "rsa_public_key",
                                "public_key": rsa_pub
                            }))
                            print("📤 RSA Public Key gönderildi")
                        continue

                    # 2. ECC ANAHTAR DEĞİŞİMİ (ECDH) - GÜNCEL HALİ
                    if packet_type == 'client_ecc_public_key':
                        client_pub = packet.get('public_key')
                        cipher_method = packet.get('method', 'aes')

                        if client_pub:
                            key_service.store_client_ecc_public_key(client_id, client_pub)
                            shared_key = key_service.get_shared_ecc_key(client_pub)

                            key_service.store_client_key(client_id, shared_key, cipher_method)

                            ws.send(json.dumps({"type": "key_exchange_ack", "status": "success"}))
                            print(f"✅ ECC El Sıkışması Tamamlandı. Metod: {cipher_method}")
                            print(f"Ortak Anahtar: {shared_key[:15]}...")
                        continue

                    # 3. RSA ANAHTAR DEĞİŞİMİ
                    if packet_type == 'key_exchange':
                        handle_key_exchange(ws, packet, client_id, key_service)
                        continue

                    # 4. RSA CLIENT PUBLIC KEY KAYDI
                    if packet_type == 'client_rsa_public_key':
                        client_public_key = packet.get('public_key')
                        if client_public_key:
                            key_service.store_client_rsa_public_key(client_id, client_public_key)
                            print("✅ Client RSA public key alındı")
                        continue

                    # 5. NORMAL MESAJLAŞMA
                    handle_message(ws, packet, client_id, key_service)

                except json.JSONDecodeError:
                    print(f"⚠️  JSON Parse Hatası")
                except Exception as e:
                    logger.error(f"❌ İşlem Hatası: {e}", exc_info=True)
                    ws.send(json.dumps({"type": "error", "message": str(e)}))

        except Exception as e:
            logger.error(f"❌ Bağlantı Hatası: {e}")
            key_service.remove_client_data(client_id)




def handle_key_exchange(ws, packet: dict, client_id: str, key_service: KeyService):
    encrypted_key = packet.get('encrypted_key')
    method = packet.get('method', Config.DEFAULT_METHOD)
    
    logger.info(f"📥 Anahtar değişim paketi alındı - Method: {method}")
    print(f"📥 Anahtar değişim paketi alındı - Method: {method}")
    print(f"📦 Şifreli anahtar uzunluğu: {len(encrypted_key) if encrypted_key else 0}")
    
    try:

        logger.info("🔓 RSA ile deşifreleme başlatılıyor...")
        print("🔓 RSA ile deşifreleme başlatılıyor...")
        symmetric_key = key_service.decrypt_symmetric_key(encrypted_key)
        logger.info(f"✅ Simetrik anahtar deşifrelendi: {symmetric_key[:20]}...")
        print(f"✅ Simetrik anahtar deşifrelendi: {symmetric_key[:20]}...")
        

        key_service.store_client_key(client_id, symmetric_key, method)
        response = MessagePacket(
            type="key_exchange_ack",
            status="success"
        )
        ws.send(json.dumps(response.to_dict()))
        
    except Exception as e:
        logger.error(f"❌ Anahtar değişimi hatası: {e}", exc_info=True)
        print(f"❌ Anahtar değişimi hatası: {e}")
        print(traceback.format_exc())
        response = MessagePacket(
            type="key_exchange_ack",
            status="error",
            message=str(e)
        )
        ws.send(json.dumps(response.to_dict()))


def handle_message(ws, packet: dict, client_id: str, key_service: KeyService):
    # 1. Paketten verileri al
    message = packet.get('message', '')
    use_library = packet.get('use_library', True)

    # 2. İstemciye ait el sıkışma ile oluşmuş anahtarı al
    client_key_data = key_service.get_client_key(client_id)

    # Güvenlik Kontrolü: Eğer el sıkışma yapılmamışsa mesajı işleme
    if not client_key_data:
        logger.warning(f"⚠️  {client_id} için anahtar bulunamadı! İşlem reddedildi.")
        ws.send(json.dumps({"type": "error", "message": "Güvenli hat kurulmadı. Lütfen tekrar bağlanın."}))
        return

    key = client_key_data['key']
    method = client_key_data['method']

    print(f"\n🔐 Mesaj İşleniyor: {method.upper()} | Mod: {'Lib' if use_library else 'Man'}")
    print(f"📨 Gelen Şifreli: {message[:50]}...")

    try:
        # 3. DEŞİFRELEME (Gelen Mesaj)
        decrypted = CipherService.decrypt_message(message, method, key, use_library)
        print(f"🔓 Çözüldü: {decrypted}")

        # 4. İŞLEME (Sunucu yanıtı ekle)
        processed = decrypted + " (sunucuda alındı)"

        # 5. ŞİFRELEME (Gidecek Yanıt)
        encrypted_response = CipherService.encrypt_message(processed, method, key, use_library)
        print(f"🔐 Yanıt Şifrelendi")

        # 6. YANIT PAKETİNİ OLUŞTUR VE GÖNDER
        response = MessagePacket(
            type="message",
            message=encrypted_response,
            method=method,
            use_library=use_library
        )
        ws.send(json.dumps(response.to_dict()))
        print(f"✅ Cevap Gönderildi")

    except Exception as e:
        logger.error(f"❌ Mesaj işleme hatası: {e}")
        ws.send(json.dumps({"type": "error", "message": "Mesaj işlenirken hata oluştu."}))

