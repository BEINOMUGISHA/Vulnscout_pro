# Setup After Frontend/Backend Separation

This guide walks you through setting up VulnScout Pro after separating the frontend and backend.

## ✅ What's Already Done

- ✓ Frontend React app created in `frontend/` directory
- ✓ Backend API routes cleaned up (removed `/war-room` route)
- ✓ Vite configuration optimized for frontend
- ✓ Frontend Vite config set to proxy API calls to backend during development

## 🧹 Cleanup Steps

### 1. Remove Old Integration Files

These files were used when frontend and backend were integrated. They're now replaced by the new separation:

```bash
# From root directory
rm -f package.json              # Old root-level Node.js config
rm -f vite.config.js            # Old root-level Vite config  
rm -f index.html                # Old root-level HTML template
rm -rf src/                      # Old root-level React source
rm -f web/templates/war_room.html  # Old war room template
rm -rf web/static/dist/         # Old build output
```

**Windows (PowerShell):**
```powershell
Remove-Item -Path package.json
Remove-Item -Path vite.config.js
Remove-Item -Path index.html
Remove-Item -Path src -Recurse
Remove-Item -Path web/templates/war_room.html
Remove-Item -Path web/static/dist -Recurse
```

### 2. Verify Frontend is Ready

```bash
cd frontend
ls -la
# Should see: package.json, vite.config.js, index.html, src/, dist/ (after build)
```

### 3. Dependency Cleanup

```bash
# Backend - clean Python environment
rm -rf venv/
python -m venv venv
source venv/bin/activate  # or: venv\Scripts\Activate.ps1 on Windows
pip install -r requirements/prod.txt

# Frontend - already set up, just verify
cd frontend
npm install
```

## 🚀 Running Locally

### Terminal 1: Backend

```bash
source venv/bin/activate  # Activate Python virtual environment
uvicorn api.main:app --reload --port 8000
```

Backend starts on http://localhost:8000

Check health: `curl http://localhost:8000/health`

### Terminal 2: Frontend

```bash
cd frontend
npm run dev
```

Frontend dev server starts on http://localhost:3000

### Open in Browser

Visit: **http://localhost:3000**

The frontend will automatically proxy API calls to http://localhost:8000/api

## 🔨 Building for Production

### Backend

No build step needed. Just install dependencies:

```bash
pip install -r requirements/prod.txt
```

Then run with a production ASGI server like Gunicorn:

```bash
pip install gunicorn
gunicorn api.main:app --workers 4 --bind 0.0.0.0:8000
```

### Frontend

Build the React app:

```bash
cd frontend
npm run build
```

Output: `frontend/dist/`

Deploy `dist/` to:
- **Option 1**: CDN (Cloudflare, AWS S3, etc.)
- **Option 2**: Static file host (nginx, Apache)
- **Option 3**: Same server as backend via reverse proxy

## 🌐 Deployment Options

### Option A: Same Server (Reverse Proxy)

Use nginx to serve both:

```nginx
# nginx.conf
upstream backend {
  server localhost:8000;
}

server {
  listen 80;
  server_name app.example.com;

  # API routes go to FastAPI
  location /api/ {
    proxy_pass http://backend;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
  }

  # Everything else is served as static files
  location / {
    root /var/www/vulnscout/frontend/dist;
    try_files $uri $uri/ /index.html;
  }
}
```

### Option B: Different Servers

- **Frontend**: Deployed to CDN or static host
- **Backend**: Running on separate server/container
- **CORS**: Configure backend to allow frontend domain

Update backend `.env`:
```
CORS_ORIGINS=["https://app.example.com"]
```

### Option C: Docker

```bash
# Build backend image
docker build -f docker/Dockerfile -t vulnscout-backend .

# Build frontend image (with nginx)
cd frontend
docker build -t vulnscout-frontend .

# Run both
docker run -p 8000:8000 vulnscout-backend
docker run -p 3000:80 vulnscout-frontend
```

## 📝 Configuration

### Backend (.env)

Create `backend/.env`:

```env
APP_NAME=VulnScout Pro
APP_ENV=production
DEBUG=false
SECRET_KEY=your-secret-key-here

# API
API_PORT=8000
API_HOST=0.0.0.0

# CORS - update with your frontend URL
CORS_ORIGINS=["http://localhost:3000"]

# Database
DATABASE_URL=postgresql://user:pass@localhost/vulnscout
```

### Frontend Development (.env.local)

Create `frontend/.env.local` (for dev only):

```env
VITE_API_BASE_URL=http://localhost:8000
```

For production, update `frontend/vite.config.js`:

```javascript
server: {
  proxy: {
    '/api': {
      target: 'https://api.example.com',  // Your backend URL
      changeOrigin: true,
    }
  }
}
```

## ✨ Verify Everything Works

### Health Checks

```bash
# Backend health
curl http://localhost:8000/health

# Frontend (in browser)
open http://localhost:3000
```

### API Test

```bash
# Test API endpoint
curl -X GET http://localhost:8000/api/scans \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Component Tests

1. **Frontend Load**: Page should load, no 404 errors
2. **API Calls**: Network tab should show requests to `/api/*`
3. **WebSocket/SSE**: Event stream should receive updates
4. **Authentication**: Should redirect to login if not authenticated

## 🐛 Troubleshooting

### Frontend Can't Connect to Backend

**Check:**
- Backend is running: `curl http://localhost:8000/health`
- Frontend proxy config: Check `frontend/vite.config.js`
- No firewall blocking port 8000
- CORS headers are correct

**Fix:**
- Make sure backend is running on port 8000
- Clear browser cache: F12 → Application → Clear storage
- Check browser console for CORS errors

### Build Fails

**Frontend:**
```bash
cd frontend
rm -rf node_modules package-lock.json
npm install
npm run build
```

**Backend:**
```bash
rm -rf venv/
python -m venv venv
source venv/bin/activate
pip install -r requirements/prod.txt
```

### Port Already in Use

**macOS/Linux:**
```bash
# Kill process on port 8000
lsof -ti:8000 | xargs kill -9

# Kill process on port 3000
lsof -ti:3000 | xargs kill -9
```

**Windows:**
```powershell
# Kill process on port 8000
Get-Process | Where-Object { $_.Handles } | Where-Object { $_Name -match 'python|node' } | stop-process

# Or find what's using the port
netstat -ano | findstr :8000
taskkill /PID <PID> /F
```

## 📚 Next Steps

1. **Review Architecture**: Read [docs/FRONTEND_BACKEND_SEPARATION.md](../docs/FRONTEND_BACKEND_SEPARATION.md)
2. **Deploy Frontend**: Follow deployment guide for your platform
3. **Set Up Database**: Configure persistent storage backend
4. **Configure Monitoring**: Set up logs, metrics, alerting
5. **Security**: Configure TLS, API keys, CORS properly

## 📖 Documentation

- [Frontend README](../frontend/README.md)
- [Architecture Guide](../docs/FRONTEND_BACKEND_SEPARATION.md)
- [API Reference](../docs/api_reference.md)
- [Deployment Guide](../docs/deployment_guide.md)

---

**Need help?** Check the docs or GitHub issues for common problems.
