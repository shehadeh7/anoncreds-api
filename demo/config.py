import os
import time
from pathlib import Path
from dotenv import load_dotenv
from cachelib.file import FileSystemCache

load_dotenv()
Path("session").mkdir(parents=True, exist_ok=True)


class Config(object):

    APP_TITLE = "AnonCreds V2 Demo"

    ENV = "development"
    SECRET_KEY = os.getenv("SECRET_KEY", "unsecured")

    DOMAIN = os.getenv("DOMAIN", "localhost:5000")
    ENDPOINT = f"http://{DOMAIN}" if DOMAIN == "localhost:5000" else f"https://{DOMAIN}"

    ASKAR_DB = os.getenv("ASKAR_DB", "sqlite://session/app.db")
    # ANONCREDS_API = "https://api.anoncreds.vc"
    ANONCREDS_API = "http://localhost:8000"

    SESSION_TYPE = "cachelib"
    SESSION_SERIALIZATION_FORMAT = "json"
    SESSION_CACHELIB = FileSystemCache(threshold=500, cache_dir="session")
    SESSION_COOKIE_NAME = "AnonCreds"
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_HTTPONLY = "True"
