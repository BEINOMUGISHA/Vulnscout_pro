"""
storage/__init__.py — Storage Package

Exports the two store classes and the mount function that wires
them into app.state during FastAPI lifespan startup.

Usage in api/main.py lifespan:
    from storage import mount_stores
    mount_stores(app)

Then in dependencies.py (already implemented):
    def get_scan_store(request: Request):
        return request.app.state.scan_store

    def get_report_store(request: Request):
        return request.app.state.report_store
"""

from storage.scan_store   import ScanStore,   get_scan_store_instance
from storage.report_store import ReportStore, get_report_store_instance
from storage.session_store import SessionStore

__all__ = ["ScanStore", "ReportStore", "SessionStore", "mount_stores"]


def mount_stores(app) -> None:
    """
    Attach ScanStore and ReportStore to app.state.
    Call once in the FastAPI lifespan startup handler.

    Both stores are created from config.storage.data_dir and will
    create their directory layouts on first use.
    """
    from config import get_config
    config = get_config()
    app.state.scan_store   = get_scan_store_instance()
    app.state.report_store = get_report_store_instance()
    app.state.session_store = SessionStore(config.storage.data_dir)