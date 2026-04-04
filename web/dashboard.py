"""
web/dashboard.py — Web Dashboard Router (SPA Mode)

Serves the VulnScout Pro React Single-Page Application (SPA).
Instead of rendering Jinja2 templates on the server, this router now acts
as a catch-all to serve the pre-built React `index.html` file from `web/static/dist`.
The React frontend handles all its own routing (via react-router-dom) while
communicating with the `/api/v1` backend endpoints.
"""

import os
from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter()

@router.get("/{full_path:path}", include_in_schema=False)
async def serve_spa(full_path: str):
    """
    Catch-all route for the React Single Page Application.
    Any GET request that hasn't been handled by /api or /static
    will fall through to here and receive the index.html.
    """
    # Exclude obvious api calls that 404'd before they hit here
    if full_path.startswith("api/"):
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="API route not found")

    # If the path looks like a static file (has an extension) and we're here, 
    # it means it wasn't found in the /static mount. Return 404 instead of index.html.
    if "." in full_path.split("/")[-1]:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Resource not found")

    # Path to the compiled Vite output
    index_path = os.path.join(os.path.dirname(__file__), "static", "dist", "index.html")
    
    # If the frontend hasn't been built yet, provide a fallback message
    if not os.path.exists(index_path):
        from fastapi.responses import HTMLResponse
        return HTMLResponse(
            status_code=503,
            content="""
                <h1>Frontend Not Built</h1>
                <p>The React SPA frontend has not been compiled.</p>
                <p>Please run <code>npm run build</code> in the <code>frontend</code> directory.</p>
            """
        )
        
    return FileResponse(index_path)
