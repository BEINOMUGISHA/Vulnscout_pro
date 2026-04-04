# Deployment Guide: Backend on Render, Frontend on GitHub Pages

## Prerequisites
- GitHub account with repository access
- Render.com account (free tier works)
- SQLite is built-in (no external DB required for basic use)

---

## Architecture Change

The frontend now uses the **backend's built-in authentication** instead of Supabase. This means:
- Login/Signup flows hit `/api/v1/auth/*` endpoints
- JWT tokens are stored in localStorage
- No Supabase dependency needed for auth

---

## Part 1: Backend Deployment on Render

### Step 1: Create requirements.txt
In the root directory, create a `requirements.txt` file:

```
-r requirements/prod.txt
```

### Step 2: Create runtime.txt
Create `runtime.txt` to specify Python version:
```
python-3.11.8
```

### Step 3: Create Render configuration (render.yaml)
Create `render.yaml` in the root:

```yaml
services:
  - type: web
    name: vulnscout-api
    env: python
    buildCommand: pip install -r requirements/prod.txt
    startCommand: uvicorn api.main:app --host 0.0.0.0 --port $PORT
    envVars:
      - key: VULNSCOUT_ENVIRONMENT
        value: production
      - key: VULNSCOUT_DEBUG
        value: "false"
      - key: VULNSCOUT_SECRET_KEY
        generateValue: true
      - key: VULNSCOUT_SCAN_ALLOW_ALL_TARGETS
        value: "false"
      - key: VULNSCOUT_AI_ENABLED
        value: "false"
      # Add your database URL if using external DB
      # - key: DATABASE_URL
      #   sync: false
```

### Step 4: Push to GitHub
```bash
git init
git add .
git commit -m "Prepare for deployment"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/vulnscout-pro.git
git push -u origin main
```

### Step 5: Deploy on Render
1. Go to [render.com](https://render.com) and sign in
2. Click "New" → "Web Service"
3. Connect your GitHub repository
4. Configure:
   - Name: `vulnscout-api`
   - Region: Choose closest to you
   - Branch: `main`
   - Build Command: `pip install -r requirements/prod.txt`
   - Start Command: `uvicorn api.main:app --host 0.0.0.0 --port $PORT`
5. Click "Create Web Service"

### Step 6: Update CORS in Backend
After getting your Render URL (e.g., `https://vulnscout-api.onrender.com`), update `api/main.py`:

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-username.github.io"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

---

## Part 2: Frontend Deployment on GitHub Pages

### Step 1: Update vite.config.ts for Production
Update `frontend/vite.config.ts`:

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  base: '/',
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'https://vulnscout-api.onrender.com',
        changeOrigin: true,
        secure: true,
      }
    }
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    },
  },
})
```

### Step 2: Build and Deploy
```bash
cd frontend
npm run build
```

### Step 3: Deploy using GitHub Actions
Create `.github/workflows/deploy.yml`:

```yaml
name: Deploy to GitHub Pages

on:
  push:
    branches: [main]
    paths: ['frontend/**']

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
          cache-dependency-path: frontend/package-lock.json
      
      - name: Install dependencies
        run: cd frontend && npm ci
      
      - name: Build
        run: cd frontend && npm run build
      
      - name: Deploy
        uses: peaceiris/actions-gh-pages@v3
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          publish_dir: ./frontend/dist
```

### Step 4: Enable GitHub Pages
1. Go to your repository settings
2. Navigate to "Pages"
3. Under "Build and deployment", select "GitHub Actions"
4. The workflow will automatically deploy on push

---

## Part 3: Final Configuration

### Update Backend CORS
After getting both URLs, update `api/main.py`:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://YOUR_USERNAME.github.io"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Environment Variables Summary

**Backend (Render):**
| Variable | Value |
|----------|-------|
| VULNSCOUT_ENVIRONMENT | production |
| VULNSCOUT_DEBUG | false |
| VULNSCOUT_SECRET_KEY | (generated) |

**Frontend (GitHub Pages):**
- No special env vars needed - API calls proxy to backend

---

## Troubleshooting

### CORS Errors
- Make sure backend `allow_origins` includes your GitHub Pages URL
- Check the exact URL (with or without www)

### API Not Reaching Backend
- Verify the proxy target in vite.config.ts
- Check Render logs for errors

### Build Failures
- Ensure Node.js version matches (use 20.x)
- Check that all dependencies are in package.json