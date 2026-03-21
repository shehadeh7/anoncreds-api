# AnonCreds API Demo

This project provides a demo implementation of an Anonymous Credentials (AnonCreds) flow, including issuer, holder, and verifier components.

---

## 🚀 Prerequisites

* Python **3.10+**
* Rust + Cargo (for cryptographic bindings)
* (Optional) Docker

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/shehadeh7/anoncreds-api.git
cd anoncreds-api
```

---

### 2. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

---

### 3. Install dependencies (one command ✅)

```bash
pip install -r requirements.txt
```

This installs all required dependencies for the demo (Flask, Aries Askar, AnonCreds bindings, etc.).

---

## ▶️ Running the Demo

Navigate to the demo directory:

```bash
cd demo
```

Run the application:

```bash
python main.py
```

---

## 🌐 Access the App

Open your browser:

```
http://localhost:5000
```

---

## 🧪 Features

This demo includes:

* Credential schema creation
* Credential issuance
* Credential storage (wallet via Aries Askar)
* Proof generation
* Proof verification
* QR code-based flows

---

## 🐳 Running with Docker (API mode)

Build the image:

```bash
docker build -t anoncreds-api .
```

Run the container:

```bash
docker run -p 8000:8000 anoncreds-api
```

Then open:

```
http://localhost:8000/docs
```

---

## ⚠️ Notes

* The **demo UI (Flask)** runs on port **5000**
* The **Docker API (FastAPI/Uvicorn)** runs on port **8000**
* These are **two different entrypoints**

---

## 🧠 Troubleshooting

### 1. Virtual environment not activated

If you see missing modules:

```
ModuleNotFoundError: No module named '...'
```

Make sure:

```bash
source venv/bin/activate
```

---

### 2. Port already in use

Change port in `main.py`:

```python
app.run(host="0.0.0.0", port=5001)
```

---

### 3. Rust issues

Verify installation:

```bash
rustc --version
cargo --version
```

---

## 📌 Recommended Usage

For demos / presentations:

```bash
cd demo
python main.py
```

This provides a full **issuer → holder → verifier** flow with a UI.

---

## 🔥 Summary

| Mode      | Command                       | Port |
| --------- | ----------------------------- | ---- |
| Demo (UI) | `python demo/main.py`         | 5000 |
| API       | `docker run -p 8000:8000 ...` | 8000 |

---

## 💡 Tip

If you modify dependencies:

```bash
pip freeze > requirements.txt
```

to keep the environment reproducible.
