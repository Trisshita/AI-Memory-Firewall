"""
AI Memory Firewall - Main Application Entry Point
==================================================
Seeds default database credentials and launches the Streamlit Web Application.
"""

import sys
import subprocess
from scripts.seed_demo import seed
from src.app import create_app

# FastAPI application instance retained for programmatic imports or testing
app = create_app()


def main():
    print("🌱 Ensuring database is initialized and seeded...")
    try:
        seed()
    except Exception as e:
        print(f"⚠️ Seed notice: {e}")

    print("🛡️ Starting AI Memory Firewall Streamlit Web Application...")
    cmd = [sys.executable, "-m", "streamlit", "run", "streamlit_app.py"]
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n🛑 AI Memory Firewall Streamlit application stopped.")


if __name__ == "__main__":
    main()
