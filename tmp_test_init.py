from api.main import create_app
import os

os.environ["VULNSCOUT_ENV"] = "development"

try:
    print("Creating app...")
    app = create_app()
    print("App created successfully.")
except Exception as e:
    print(f"Failed to create app: {e}")
    import traceback
    traceback.print_exc()
