"""
AI Memory Firewall
==================
Main application entry point.
Automated launcher for database seeding, backend server, and frontend dashboard.
"""

import os
import sys
import subprocess
from src.app import create_app

app = create_app()


def seed_database():
    """Runs seed logic if database tables / initial data are not present."""
    try:
        from scripts.seed_demo import seed
        print("🌱 Checking & seeding default database credentials...")
        seed()
    except Exception as e:
        print(f"⚠️ Seed status: {e}")


def launch_frontend():
    """Launches the frontend Vite dev server in a background process."""
    frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")
    if os.path.exists(frontend_dir):
        print("🚀 Launching Frontend Vite server...")
        cmd = "npm run dev"
        return subprocess.Popen(cmd, cwd=frontend_dir, shell=True)
    return None


if __name__ == "__main__":
    import uvicorn

    # 1. Automatically seed DB (if not already seeded)
    seed_database()

    # 2. Automatically launch Frontend dev server
    frontend_proc = launch_frontend()

    try:
        # 3. Start FastAPI backend server
        print("🔥 Starting FastAPI backend on http://localhost:8000 ...")
        uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
    finally:
        if frontend_proc:
            print("\n🛑 Stopping Frontend server...")
            try:
                if sys.platform == "win32":
                    subprocess.call(["taskkill", "/F", "/T", "/PID", str(frontend_proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    frontend_proc.terminate()
            except Exception:
                pass

