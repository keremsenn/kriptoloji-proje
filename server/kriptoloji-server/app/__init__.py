
from flask import Flask
from flask_cors import CORS
from flask_sock import Sock
from app.utils.logger import setup_logging
from app.services.key_service import KeyService
from config import Config


def create_app():
    app = Flask(__name__)
    CORS(app)
    sock = Sock(app)

    setup_logging(Config.LOG_LEVEL)
    key_service = KeyService()
    key_service.initialize()

    from app.routes import web, websocket
    app.register_blueprint(web.bp)
    websocket.register_socket_routes(sock, key_service)
    
    return app, sock

