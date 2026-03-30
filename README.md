# JWKS Server (Project 2)

Extends Project 1 with a **SQLite-backed** key store.

## What it does
- Runs on **port 8080**
- `GET /.well-known/jwks.json` — returns all unexpired public keys from the DB
- `POST /auth` — returns a valid RS256 JWT signed by an unexpired key from the DB
- `POST /auth?expired=true` — returns a JWT signed by the expired key (with an expired `exp`)
- JWTs include `kid` in the header matching the DB row's primary key

## Database
- File: `totally_not_my_privateKeys.db` (SQLite, created automatically on start)
- Schema:
  ```sql
  CREATE TABLE IF NOT EXISTS keys(
      kid INTEGER PRIMARY KEY AUTOINCREMENT,
      key BLOB NOT NULL,
      exp INTEGER NOT NULL
  )
  ```
- Private keys are stored as **PKCS1 PEM** text
- All queries use parameterized placeholders to prevent SQL injection

## Authentication
The `/auth` endpoint accepts credentials in two formats (neither is actually
validated — this is mock authentication):
- **HTTP Basic Auth**: `Authorization: Basic <base64(user:pass)>`
- **JSON body**: `{"username": "userABC", "password": "password123"}`

## Run it
```bash
go mod tidy
go run .
```
Server starts at: `http://localhost:8080`

## Try it
```bash
curl -s http://localhost:8080/.well-known/jwks.json
curl -s -X POST http://localhost:8080/auth
curl -s -X POST "http://localhost:8080/auth?expired=true"

# Basic Auth
curl -s -X POST -u userABC:password123 http://localhost:8080/auth

# JSON body
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"username":"userABC","password":"password123"}' \
  http://localhost:8080/auth
```

## Tests + coverage
```bash
go test ./... -cover
```
82% statement coverage.
