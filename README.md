# FastAPI JWT Auth API

Secure user authentication with JWT.

## Endpoints
- `POST /register` → `{username, password}`
- `POST /login` → JWT token
- `GET /users/me` → (protected)

## Run Locally
```bash
uvicorn main:app --reload