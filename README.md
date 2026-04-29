# MAGMA PAY

Flask-based processing simulator with:

- registration and login
- user dashboard with balance, transactions, P2P and trading simulation
- admin panel for balance control, spread control and realtime notifications
- JSON-backed state without a database

## Run

```powershell
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`

## Demo accounts

- user: `test@magma.com` / `123456`
- admin: `admin@magma.com` / `admin`

## Image limits

Uploads are disabled in MVP, but the project already defines a policy for future media:

- formats: PNG, JPG, JPEG, WebP
- default max file size: 5 MB
- recommended avatar limit: 2 MB
