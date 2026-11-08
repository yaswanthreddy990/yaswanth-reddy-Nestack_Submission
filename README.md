
# Nestack Secure Records API

## Overview
A secure multi-tenant Records API developed using Python, Flask and SQLite for the Nestack Cybersecurity Assessment.

## Technology Stack
- Python
- Flask
- SQLite
- bcrypt
- pytest

## Setup Instructions

### 1. Create a virtual environment
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies
```powershell
python -m pip install -r requirements.txt
```

### 3. Start the application
```powershell
python app.py
```

API address: http://127.0.0.1:5000

### 4. Create an administrator
```powershell
python create_admin.py
```

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| POST | /register | Register a user |
| POST | /login | Login |
| POST | /records | Create a record |
| GET | /records/:id | Read a record |

Protected endpoints require a Bearer session token.

## Security Implementation

### Password Security
Passwords are hashed using bcrypt with a work factor of 12 and unique salts. Plaintext passwords are never stored.

### Session Management
The application uses cryptographically random opaque session tokens. Only SHA-256 hashes are stored in SQLite. Sessions expire after 12 hours.

### IDOR Prevention
Every record belongs to a particular user. Normal users can read only their own records. Unauthorized record access returns HTTP 404.

### Admin Authorization
Users receive the user role during registration. Role fields supplied by clients are rejected. Admin accounts are provisioned through a separate local script.

### Brute-Force Protection
Five incorrect login attempts trigger a 15-minute account lockout. Further attempts return HTTP 429.

### Input Validation
The application validates data types, required fields and input lengths. Request bodies are limited to 16 KB.

### SQL Injection Prevention
Parameterized SQL queries are used for database access.

## Threat Model

### User Database Disclosure
An attacker who obtains the users table can see usernames, bcrypt password hashes, roles and account metadata.

They cannot directly recover plaintext passwords from bcrypt hashes. However, weak passwords may still be vulnerable to offline guessing.

### Session Database Disclosure
The sessions table stores SHA-256 hashes rather than original session tokens. A stolen valid raw token could still be used until it expires.

### IDOR Attack
Changing a record ID does not grant access. The application checks record ownership or administrator privileges before returning data.

### Privilege Escalation
Users cannot assign themselves the admin role during registration.

### Brute-Force Attack
Failed login attempts are tracked per account. Five failures trigger temporary account lockout.

## Security Testing

Run automated tests:

```powershell
python -m pytest -v
```

Latest local test result: 10 passed.

Tests cover password hashing, session integrity, IDOR, admin access, privilege escalation, login lockout, authentication and input validation.

## Production Hardening

Before production deployment, further protections should include HTTPS, session revocation, security audit logging, restricted database access, backups and secure administrator operations.

## Author
Nestack Cybersecurity Internship Assessment
