# Separated Frontend & Backend Architecture

VulnScout Pro now uses a **fully separated frontend and backend** architecture. This allows independent development, deployment, and scaling of each component.

## Directory Structure

```
vulnscout_pro/
├── backend/                    # FastAPI backend (this directory)
│   ├── api/                   # REST API routes
│   ├── web/                   # Legacy web dashboard templates (Jinja2)
│   ├── core/                  # Core scanning engine
│   ├── storage/               # Data persistence layer
│   ├── requirements/          # Python dependencies
│   └── run.py                 # Backend entry point
│
├── frontend/                  # React frontend (separate application)
│   ├── src/                   # React source code
│   │   ├── WarRoom.jsx       # War Room component
│   │   └── main.jsx          # Entry point
│   ├── package.json          # Node.js dependencies
│   ├── vite.config.js        # Vite bundler config
│   └── index.html            # HTML template
│
└── docs/                      # Documentation
    └── ARCHITECTURE.md        # This file
```

## Running Both Components

### Backend (FastAPI)

```bash
# From root directory
python -m venv venv
source venv/bin/activate  # or: venv\Scripts\Activate.ps1 on Windows

pip install -r requirements/prod.txt

# Start the server
uvicorn api.main:app --host 0.0.0.0 --port 8000

# Or with auto-reload for development
uvicorn api.main:app --reload --port 8000
```

Backend runs on **http://localhost:8000**

### Frontend (React)

```bash
# From frontend/ directory
npm install
npm run dev   # Development server on http://localhost:3000
npm run build # Production build to frontend/dist/
```

Frontend dev server runs on **http://localhost:3000**

## Communication Flow

```
┌─────────────────────────────────────────────────────────┐
│                    User Browser                         │
└────────────────────┬────────────────────────────────────┘
                     │
                     ├─ GET / POST / etc. requests
                     │
        ┌────────────v────────────┐
        │  React Frontend (3000)   │
        │  - War Room UI           │
        │  - Dashboard (future)    │
        │  - Settings             │
        └────────────┬────────────┘
                     │
                     ├─ HTTP REST API calls
                     │ (proxied during dev)
                     │
        ┌────────────v────────────────┐
        │  FastAPI Backend (8000)      │
        │  - Scan orchestration        │
        │  - Authentication           │
        │  - Report generation         │
        │  - User management          │
        └─────────────────────────────┘
```

**Development:**
- Frontend dev server proxies `/api/*` requests to `http://localhost:8000`
- Configured in [frontend/vite.config.js](../../frontend/vite.config.js)

**Production:**
- Frontend is fully static files (HTML, JS, CSS)
- Can be served from any static host (S3, CDN, nginx, etc.)
- Backend API remains at original URL

## API Integration

The frontend communicates with the backend exclusively via REST API endpoints under `/api/`:

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `POST /api/auth/refresh` - Refresh token

### Scans
- `POST /api/scans` - Create a new scan
- `GET /api/scans/{scan_id}` - Get scan details
- `GET /api/scans/{scan_id}/findings` - Get findings
- `GET /api/scans/{scan_id}/events` - Get events (SSE stream)
- `DELETE /api/scans/{scan_id}` - Cancel/delete scan

### Reports
- `GET /api/reports` - List reports
- `GET /api/reports/{report_id}` - Get report details
- `POST /api/reports/{report_id}/export` - Export (PDF, JSON, CSV)

See [docs/api_reference.md](./api_reference.md) for complete API specification.

## CORS Configuration

For production, ensure the backend CORS middleware is configured to accept requests from your frontend domain:

```python
# In api/main.py
CORSMiddleware(
    allow_origins=["https://your-frontend-domain.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

## Deployment Strategies

### Strategy 1: Same-Origin (Recommended)

Both frontend and backend served from the same origin via reverse proxy:

```
User → nginx (port 80/443)
  ├─ /api/* → localhost:8000 (backend)
  └─ /* → static files (frontend)
```

**nginx example:**
```nginx
upstream backend {
  server localhost:8000;
}

server {
  listen 80;
  server_name app.example.com;

  location /api/ {
    proxy_pass http://backend;
    proxy_set_header Host $host;
  }

  location / {
    root /var/www/vulnscout-frontend/dist;
    try_files $uri /index.html;
  }
}
```

### Strategy 2: Different Hosts

Frontend and backend on separate domains/servers:

```
Frontend: https://app.example.com (static host or frontend server)
Backend:  https://api.example.com (FastAPI server)
```

Ensure backend CORS allows the frontend domain.

### Strategy 3: Containerized (Docker)

```bash
# Backend container
docker run -p 8000:8000 vulnscout-backend

# Frontend container (nginx serving static files)
docker run -p 3000:80 vulnscout-frontend

# Or docker-compose
docker-compose up
```

## Development Workflow

### Add a New API Feature

1. Backend: Add the route in `api/routes/*.py`
2. Frontend: Call the API from React:

```javascript
// In a React component
const response = await fetch('/api/scans', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ target: 'https://example.com' })
});
const data = await response.json();
```

### Hot Reload During Development

- **Frontend**: Changes to JSX/CSS auto-reload on port 3000
- **Backend**: Use `--reload` flag with uvicorn for auto-reload

### Build for Production

1. **Backend:**
   ```bash
   pip install -r requirements/prod.txt
   ```
   (No build step needed, pure Python)

2. **Frontend:**
   ```bash
   cd frontend
   npm run build
   # Output: frontend/dist/
   ```

   Deploy `frontend/dist/` to your static file host.

## Environment Configuration

### Backend (.env)

```
APP_NAME=VulnScout Pro
APP_ENV=production
DEBUG=false

# API
API_PORT=8000
API_HOST=0.0.0.0

# CORS
CORS_ORIGINS=["https://app.example.com"]

# Database
DATABASE_URL=postgresql://user:pass@localhost/vulnscout

# Authentication
SECRET_KEY=your-secret-key-here
```

### Frontend (.env)

```
VITE_API_BASE_URL=https://api.example.com
VITE_APP_NAME=VulnScout Pro
```

Add `.env` to `frontend/` and update `frontend/vite.config.js` to use these variables.

## Database & Persistence

- **Storage**: All scan data, findings, users are stored via `/storage/` layer
- **Shared state**: Backend maintains authoritative state
- **Frontend**: Reads state via API, no local persistence of scan data
- **Sessions**: JWT-based authentication (stateless)

## Monitoring & Logging

- **Backend**: Structured logging via Python logging (AsyncIO compatible)
- **Frontend**: Browser console logs + optional error tracking (Sentry, etc.)
- Both communicate health status via `/health` endpoint

## Troubleshooting

### Frontend Can't Reach Backend

**Development:**
- Check vite.config.js proxy setting: should point to `http://localhost:8000`
- Ensure backend is running: `curl http://localhost:8000/health`

**Production:**
- Check CORS headers: `curl -H "Origin: https://app.example.com" https://api.example.com/health`
- Verify firewall allows traffic between frontend and backend hosts

### API Returns 401/403

- Frontend token may be expired → refresh token
- Check auth headers in network tab (Authorization: Bearer ...)
- Verify token not removed from localStorage

### Frontend Build Fails

```bash
cd frontend
rm -rf node_modules package-lock.json
npm install
npm run build
```

## Next Steps

1. **Remove old integrated files:**
   - Delete `src/` (root)
   - Delete `package.json` (root)
   - Delete `vite.config.js` (root)
   - Delete `index.html` (root)
   - Delete `web/templates/war_room.html`
   - Delete `web/static/dist/`

2. **Deploy frontend separately:**
   - Build: `cd frontend && npm run build`
   - Host `frontend/dist/` on CDN or static server

3. **Update backend configuration:**
   - Set `CORS_ORIGINS` to frontend domain
   - Configure persistent storage
   - Set up monitoring/logging

4. **Database setup:**
   - Run migrations for persistent storage
   - Configure backup strategy

## References

- [Frontend README](../../frontend/README.md)
- [Backend README](../../README.md)
- [API Reference](./api_reference.md)
- [Deployment Guide](./deployment_guide.md)
