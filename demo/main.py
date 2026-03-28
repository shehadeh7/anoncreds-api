from app import create_app
from app.plugins.anoncreds import AnonCredsApi
from asyncio import run as _await

app = create_app()

if __name__ == "__main__":
    try:
        _await(AnonCredsApi().provision())
    except Exception as e:
        print(f"⚠ Provision skipped ({e}). The e2e demo at /e2e does not require it.")
    app.run(host="0.0.0.0", port="5000", debug=True)
