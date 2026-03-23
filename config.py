import os
from dotenv import load_dotenv
from pydantic_settings import BaseSettings

load_dotenv()


class Settings(BaseSettings):

    APP_TITLE: str = "AnonCreds API"
    APP_VERSION: str = "v2"

    SECRET_KEY: str = os.getenv("SECRET_KEY", "unsecured")

    DOMAIN: str = os.getenv("DOMAIN", "localhost:8000")
    ASKAR_DB: str = os.getenv("ASKAR_DB", "sqlite://app.db")

    BBS_BLINDER: str = (
        "0000000000000000000000000000000000000000000000000000000000000000"
    )

    TEST_VALUES: dict = {
        "cred_id": "zQmb5W91ceoJoRD6DaDLfrRJLkm7H78EaTHCSJkHdHW8Kyh",
        "schema_id": "zQmb5W91ceoJoRD6DaDLfrRJLkm7H78EaTHCSJkHdHW8Kyh",
        "subject_id": "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
        "accumulator": "a68f6b3e3c4d1174c69711341a0f8ca3dec79d2b6de727174541b74e270c8a24a2e8bf69b3cacc86cb05dc6078b2a0ea",
        "encryption_key": "82f2163bae250752cb1317e14c5266ca68017ee1168771f16571c5d56897980fc93d12981eb81e1f600cc9488d2358c9",
        "decryption_key": "6abf3b1e0b7fed502ce25951986a320347d280c1e7e2c336ee528c7e46bd3832",
        "verification_method": "did:web:api.anoncreds.vc:issuers:demo#0",
    }


settings = Settings()
