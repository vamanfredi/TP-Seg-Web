import os
from waitress import serve
from . import create_app

if __name__ == "__main__":
    serve(create_app(restore_client_password=True), host=os.environ.get("APP_HOST", "127.0.0.1"), port=8000, threads=4)
