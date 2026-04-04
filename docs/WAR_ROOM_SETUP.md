# War Room War Room - React Frontend Setup

The **War Room** is a real-time attack surface visualization and scanning interface built with React and Vite. This guide explains how to set it up and integrate it with your VulnScout Pro instance.

## Quick Start

### Prerequisites

-   Node.js 16+ installed
-   Python FastAPI backend running
-   npm or yarn package manager

### 1. Install Dependencies

From the root directory of the project:

```bash
npm install
```

This will install React, ReactDOM, and Vite with their dependencies.

### 2. Build the Frontend

To create a production build:

```bash
npm run build
```

This generates the compiled React app in `web/static/dist/` which FastAPI will serve.

For development with hot reloading:

```bash
npm run dev
```

The dev server will run on `http://localhost:5173` and proxy API requests to `http://localhost:8000`.

### 3. Access the War Room

Once the FastAPI backend is running and the frontend is built, navigate to:

```
http://localhost:8000/war-room
```

You will need to be logged in. The War Room interface will load with:

-   **Left Panel**: Interactive network graph visualization showing discovered URLs and their vulnerability status
-   **Right Panel**: Live findings feed, severity breakdown, and event log
-   **Top Bar**: Controls for scan speed, elapsed time, and statistics

## Project Structure

```
vulnscout_pro/
├── src/
│   ├── WarRoom.jsx          # Main War Room component
│   └── main.jsx              # React entry point
├── web/
│   ├── static/
│   │   └── dist/             # Vite build output (generated)
│   └── templates/
│       └── war_room.html     # Template that loads the React app
├── package.json              # Node.js dependencies
├── vite.config.js            # Vite configuration
└── index.html                # Root HTML for dev server
```

## Development

### Component Analysis

The **WarRoom.jsx** component includes:

-   **Canvas Rendering**: Real-time visualization of the attack surface using HTML5 Canvas
-   **Simulation Engine**: Demonstrates the scanning flow with mock data generation
-   **State Management**: Uses React hooks (useState, useRef, useCallback, useEffect)
-   **Animation Loop**: requestAnimationFrame for smooth 60fps rendering
-   **Responsive Layout**: Flexbox-based responsive design that adapts to window resize

### Key Features

1. **Attack Surface Map**: Visualizes discovered URLs as nested circular rings by crawl depth
2. **Vulnerability Indicators**: Color-coded nodes showing scan status and vulnerability severity
3. **Live Findings Feed**: Real-time display of discovered vulnerabilities
4. **Event Log**: Chronological log of scan activities
5. **CVSS Meter**: Visual representation of the maximum CVSS score
6. **Threat Pulse**: Red flash animation on critical findings
7. **Speed Controls**: Adjustable scan simulation speed (0.5x - 3x)

## Deployment

### Production Build

The `npm run build` command outputs to `web/static/dist/`:

-   `dist/main.js` - Bundled and minified JavaScript
-   `dist/main.css` - Extracted CSS (if any)

FastAPI serves these static files when you visit `/war-room`.

### Integration with FastAPI

The War Room template (`web/templates/war_room.html`) includes a script tag that loads the React app:

```html
<script type="module" src="{{ static_url }}/dist/main.js"></script>
```

This is automatically handled by the `/war-room` route in `web/dashboard.py`.

## Customization

### Change Target URL

Edit the `targetUrl` state in `WarRoom.jsx`:

```javascript
const [targetUrl] = useState("https://your-target.com");
```

### Adjust Colors

Modify the color constants at the top of `WarRoom.jsx`:

```javascript
const COAL = "#0a0c0e";      // Background
const AMBER = "#f59e0b";     // Primary accent
const RED = "#ef4444";       // Critical severity
```

### Connect to Real Scan Data

To connect to actual scan data from your FastAPI backend, modify the `startScan` function to call your API instead of the simulation:

```javascript
const startScan = useCallback(async () => {
  const response = await fetch('/api/scans', { method: 'POST' });
  const scan = await response.json();
  // Update state with real scan data
}, []);
```

## Troubleshooting

### Module not found errors

Ensure `node_modules` is installed:

```bash
npm install
```

### Build fails with syntax errors

Check your Node.js version:

```bash
node --version   # Should be 16.0.0 or higher
```

### Static files not loading

After building, verify that `web/static/dist/main.js` exists. If not, rebuild:

```bash
rm -rf web/static/dist
npm run build
```

### Hot reload not working in dev mode

Ensure Vite dev server is running on a different port than FastAPI (default: 5173).

## Next Steps

1. **Connect real scan data**: Integrate the War Room with live scan endpoints
2. **Add WebSocket support**: Real-time updates for findings as they're discovered
3. **Performance tuning**: Optimize canvas rendering for large attack surfaces (100+ URLs)
4. **Export functionality**: Download scan visualization as PNG/SVG
5. **Mobile responsiveness**: Adapt the layout for tablet and mobile viewing

## Documentation

-   [Vite Documentation](https://vitejs.dev)
-   [React Hooks API](https://react.dev/reference/react)
-   [Canvas API](https://developer.mozilla.org/en-US/docs/Web/API/Canvas_API)
