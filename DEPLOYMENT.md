# FluxEngine Deployment Guide

---

## Prerequisites

- Python 3.9+
- Docker (optional)
- A server or cloud host (Railway, Render, Fly.io, VPS)

---

## 1. Generate a Secret Key

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

## 2. Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env`:

```env
DEBUG=False
SECRET_KEY=<your generated key>
ALLOWED_ORIGINS=["https://yourdomain.com"]
DATABASE_PATH=./data/fluxengine.db
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

**Required before going live:**
- `SECRET_KEY` - must not be the placeholder default
- `DEBUG=False`
- `ALLOWED_ORIGINS` - set to your actual frontend domain

---

## 3. Option A - Docker (Recommended)

### Single container

```bash
docker build -t fluxengine .

docker run -d \
  --name fluxengine \
  -p 8000:8000 \
  --env-file .env \
  -v fluxengine_data:/app/data \
  --restart unless-stopped \
  fluxengine
```

### Docker Compose

```bash
docker compose up -d
```

Check it's up:

```bash
curl http://localhost:8000/health
# {"status":"healthy","service":"FluxEngine"}
```

---

## 4. Option B - Without Docker

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -r requirements.txt

uvicorn main:app --host 0.0.0.0 --port 8000
```

---

## 5. Deploy to Railway

1. Push your code to GitHub
2. Go to railway.app → New Project → Deploy from GitHub
3. Select your repo
4. Go to Variables tab → add all values from your `.env`
5. Railway auto-detects the Dockerfile and deploys

---

## 6. Deploy to Render

1. Go to render.com → New → Web Service
2. Connect your GitHub repo
3. Set:
   - **Runtime:** Docker
   - **Port:** 8000
4. Add environment variables in the dashboard
5. Add a persistent disk mounted at `/app/data`

---

## 7. Seed the Database

```bash
python scripts/seed_db.py
```

Or via Docker:

```bash
docker exec -it fluxengine python scripts/seed_db.py
```

---

## 8. Verify

```bash
curl https://yourdomain.com/health

curl -X POST https://yourdomain.com/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"strongpassword","full_name":"Admin","role":"admin"}'

curl -X POST https://yourdomain.com/api/auth/login \
  -d "username=admin@example.com&password=strongpassword"
```

---

## 9. Data Persistence

DuckDB stores everything in a single file at `DATABASE_PATH`. Back this file up.

Backup:

```bash
curl -H "Authorization: Bearer <admin_token>" \
  https://yourdomain.com/api/admin/backup \
  --output backup.db
```

Restore:

```bash
curl -X POST \
  -H "Authorization: Bearer <admin_token>" \
  -F "file=@backup.db" \
  https://yourdomain.com/api/admin/restore
```

---

## 10. Production Checklist

- [ ] `SECRET_KEY` is randomly generated
- [ ] `DEBUG=False`
- [ ] `ALLOWED_ORIGINS` set to your actual frontend domain
- [ ] Data volume is persistent
- [ ] Backup schedule in place
- [ ] HTTPS enabled
- [ ] API docs disabled or protected (`/docs`)

---

## API Docs

Available at `/docs` when the server is running.

To disable in production:

```python
app = FastAPI(
    docs_url=None if not settings.DEBUG else "/docs",
    redoc_url=None if not settings.DEBUG else "/redoc",
)
```
