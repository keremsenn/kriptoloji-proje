
from app import create_app
from config import Config

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("Kriptoloji Projesi - Sifreli Chat Sunucusu Baslatiliyor...")
    print("=" * 60)
    
    app, sock = create_app()
    
    print("Localhost: ws://localhost:5000/ws")
    print("Android Emulator: ws://10.0.2.2:5000/ws")
    print("HTTP: http://localhost:5000/")
    print("=" * 60 + "\n")

    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG,
        use_reloader=False
    )


