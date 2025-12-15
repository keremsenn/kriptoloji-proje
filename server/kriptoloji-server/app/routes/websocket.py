
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
            rsa_public_key = key_service.get_rsa_public_key()
            if rsa_public_key:
                initial_message = MessagePacket(
                    type="rsa_public_key",
                    public_key=rsa_public_key
                )
                ws.send(json.dumps(initial_message.to_dict()))
                logger.info("📤 RSA public key gönderildi")
                print("📤 RSA public key gönderildi")
            
            while True:
                data = ws.receive()
                if data is None:
                    logger.info(f"❌ İstemci bağlantısını kapattı: {client_addr}")
                    print(f"\n❌ Bağlantı kapandı: {client_addr}\n")
                    key_service.remove_client_key(client_id)
                    key_service.remove_client_rsa_public_key(client_id)
                    break
                
                print("-" * 60)
                print(f"📥 RAW DATA: {data[:200]}...")
                
                try:
                    packet = json.loads(data)
                    packet_type = packet.get('type', 'message')
                    
                    if packet_type == 'key_exchange':
                        handle_key_exchange(ws, packet, client_id, key_service)
                        continue
                    
                    if packet_type == 'client_rsa_public_key':
                        # Client'ın RSA public key'ini al
                        client_public_key = packet.get('public_key')
                        if client_public_key:
                            key_service.store_client_rsa_public_key(client_id, client_public_key)
                            logger.info("✅ Client RSA public key alındı")
                            print("✅ Client RSA public key alındı")
                        continue

                    handle_message(ws, packet, client_id, key_service)
                    
                except json.JSONDecodeError as e:
                    logger.warning(f"JSON parse başarısız: {data}")
                    print(f"⚠️  JSON Parse Hatası: {e}")
                    error_response = MessagePacket(
                        type="error",
                        message="JSON Parse Hatası",
                        error=True
                    )
                    ws.send(json.dumps(error_response.to_dict()))
                except Exception as e:
                    logger.error(f"❌ İşlem Hatası: {e}", exc_info=True)
                    print(f"❌ İşlem Hatası: {e}")
                    error_response = MessagePacket(
                        type="error",
                        message=f"Sunucu Hatası: {str(e)}",
                        error=True
                    )
                    ws.send(json.dumps(error_response.to_dict()))
        
        except Exception as e:
            logger.error(f"❌ Bağlantı Hatası: {e}", exc_info=True)
            print(f"❌ HATA: {e}\n")
            key_service.remove_client_key(client_id)


def handle_key_exchange(ws, packet: dict, client_id: str, key_service: KeyService):
    """Anahtar değişim işlemini yönet"""
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

    message = packet.get('message', '')
    method = packet.get('method', Config.DEFAULT_METHOD)
    use_library = packet.get('use_library', Config.DEFAULT_USE_LIBRARY)

    if method == 'rsa':
        try:
            from cipher.rsa import RSACipher
            
            if use_library:
                private_key = key_service.get_rsa_private_key()
                if not private_key:
                    raise ValueError("RSA private key bulunamadı")
                logger.info("🔓 RSA ile mesaj deşifreleniyor... (Kütüphaneli)")
                print("🔓 RSA ile mesaj deşifreleniyor... (Kütüphaneli)")
                decrypted = RSACipher.decrypt(message, private_key, use_library)
            else:
                public_key = key_service.get_rsa_public_key()
                if not public_key:
                    raise ValueError("RSA public key bulunamadı")
                logger.info("🔓 RSA ile mesaj deşifreleniyor... (Manuel)")
                print("🔓 RSA ile mesaj deşifreleniyor... (Manuel)")
                decrypted = RSACipher.decrypt(message, public_key, use_library)
            
            print(f"🔓 Çözüldü: {decrypted}")
        except Exception as e:
            print(f"❌ RSA Deşifreleme Hatası: {e}")
            logger.error(f"RSA deşifreleme hatası: {e}", exc_info=True)
            decrypted = f"[HATA] {str(e)}"
        
        # İşle
        processed = decrypted + " (sunucuda alındı)"
        print(f"🔄 İşlendi: {processed}")

        client_public_key = key_service.get_client_rsa_public_key(client_id)
        if client_public_key:
            try:
                from cipher.rsa import RSACipher
                logger.info(f"🔐 RSA ile yanıt şifreleniyor... (Manuel: {not use_library})")
                print(f"🔐 RSA ile yanıt şifreleniyor... (Manuel: {not use_library})")
                encrypted_response = RSACipher.encrypt(processed, client_public_key, use_library)
                print(f"✅ RSA ile yanıt şifrelendi")
            except Exception as e:
                logger.error(f"❌ RSA yanıt şifreleme hatası: {e}", exc_info=True)
                print(f"❌ RSA yanıt şifreleme hatası: {e}")
                encrypted_response = processed
        else:
            encrypted_response = processed
            logger.warning("⚠️  RSA ile yanıt şifrelenemedi (client public key yok)")
            print("⚠️  RSA ile yanıt şifrelenemedi (client public key yok)")
        
    else:
        client_key_data = key_service.get_client_key(client_id)
        if client_key_data:
            key = client_key_data['key']
            method = client_key_data['method']
        else:
            key = CipherService.get_default_key(method)
            logger.warning(f"⚠️  İstemci anahtarı bulunamadı, varsayılan kullanılıyor")
        
        logger.debug(f"📨 Paket alındı - Method: {method}, Use Library: {use_library}")
        print(f"🔐 Şifreleme Yöntemi: {method}")
        print(f"📚 Kütüphane Modu: {'Evet' if use_library else 'Hayır (Manuel)'}")
        print(f"📨 Şifreli Mesaj: {message[:100]}...")

        try:
            decrypted = CipherService.decrypt_message(message, method, key, use_library)
            print(f"🔓 Çözüldü: {decrypted}")
        except Exception as e:
            print(f"❌ Deşifreleme Hatası: {e}")
            logger.error(f"Deşifreleme hatası: {e}", exc_info=True)
            decrypted = f"[HATA] {str(e)}"
        
        processed = decrypted + " (sunucuda alındı)"
        print(f"🔄 İşlendi: {processed}")

        try:
            encrypted_response = CipherService.encrypt_message(processed, method, key, use_library)
            print(f"🔐 Şifreli Cevap: {encrypted_response[:100]}...")
        except Exception as e:
            print(f"❌ Şifreleme Hatası: {e}")
            logger.error(f"Şifreleme hatası: {e}", exc_info=True)
            encrypted_response = processed

    response = MessagePacket(
        type="message",
        message=encrypted_response,
        method=method,
        use_library=use_library
    )
    
    print(f"📤 Gönderiliyor: {json.dumps(response.to_dict())[:200]}...")
    ws.send(json.dumps(response.to_dict()))
    print(f"✅ Cevap Gönderildi")

