# Project 14: End-to-End Encrypted Chat Application

Real-Time Chat Application with **End-to-End Encryption, Forward Secrecy, and Message Authentication**.

The complete project implementation, source code, and virtual environment are located in the `CN_updated` directory.

## Quick Start (Windows PowerShell)

```powershell
# 1. Navigate to the project directory
Set-Location "C:\Users\pjasw\OneDrive\Desktop\End_to_End_Encrypted_Chat_Application_Updated\CN_updated"

# 2. Activate virtual environment
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1

# 3. Start the application server
$env:JWT_SECRET_KEY = [guid]::NewGuid().ToString("N") + [guid]::NewGuid().ToString("N")
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Open <http://127.0.0.1:8000/> in your browser (and an Incognito window for the second user).

## Run Automated Tests

```powershell
Set-Location "C:\Users\pjasw\OneDrive\Desktop\End_to_End_Encrypted_Chat_Application_Updated\CN_updated"
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1

# Run backend Python tests (16 tests):
.\venv\Scripts\python.exe -m pytest -v

# Run frontend Web Crypto API tests (6 tests):
node --test frontend\tests\crypto.test.js frontend\tests\e2e_crypto_integration.test.js
```

See [CN_updated/README.md](./CN_updated/README.md) and [CN_updated/START_HERE_WINDOWS.md](./CN_updated/START_HERE_WINDOWS.md) for full module documentation and demonstration instructions.

