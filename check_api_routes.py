import sys
import os
from pathlib import Path

# Add project root to PYTHONPATH
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from api.main import create_app

app = create_app()

print("Registered Routes:")
for route in app.routes:
    # hasattr(route, 'path') check
    path = getattr(route, 'path', 'N/A')
    methods = getattr(route, 'methods', 'N/A')
    name = getattr(route, 'name', 'N/A')
    print(f"{methods} {path} ({name})")
