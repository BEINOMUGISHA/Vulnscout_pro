import sys
import os
from pathlib import Path

# Add project root to PYTHONPATH
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from api.main import create_app

app = create_app()

print("Registered Routes:")
for route in app.routes:
    path = getattr(route, 'path', 'N/A')
    if 'auth' in path or 'login' in path:
        methods = getattr(route, 'methods', 'N/A')
        print(f"{methods} {path}")
