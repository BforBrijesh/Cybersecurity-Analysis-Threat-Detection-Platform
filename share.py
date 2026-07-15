"""
CyberShield AI — Public Link Generator
Starts the app AND creates a public URL anyone can open.

Install once:
    py -3.11 -m pip install pyngrok

Run:
    py -3.11 share.py
"""

import subprocess
import sys
import time
import os

PORT = 8501

def install_pyngrok():
    print("Installing pyngrok...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyngrok", "-q"])

def main():
    # Try to import pyngrok
    try:
        from pyngrok import ngrok, conf
    except ImportError:
        install_pyngrok()
        from pyngrok import ngrok, conf

    print("\n" + "="*60)
    print("  🛡️  CyberShield AI — Public Link Generator")
    print("="*60)

    # Start streamlit in background
    print(f"\n▶  Starting CyberShield AI on port {PORT}...")
    streamlit_process = subprocess.Popen(
        [sys.executable, "-m", "streamlit", "run", "app.py",
         "--server.port", str(PORT),
         "--server.headless", "true",
         "--server.enableCORS", "false",
         "--server.enableXsrfProtection", "false",
         "--browser.gatherUsageStats", "false"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    print("⏳  Waiting for server to start...")
    time.sleep(4)

    # Create ngrok tunnel
    print("🌐  Creating public tunnel via ngrok...")
    try:
        tunnel = ngrok.connect(PORT, "http")
        public_url = tunnel.public_url

        print("\n" + "="*60)
        print("  ✅  YOUR PUBLIC LINK IS READY!")
        print("="*60)
        print(f"\n  🔗  {public_url}")
        print(f"\n  Share this link with anyone — they can open it")
        print(f"  in any browser and create their own account.\n")
        print("  Demo accounts:")
        print("  👑  Admin:   admin / admin123")
        print("  🔵  Analyst: analyst / analyst123")
        print("\n" + "="*60)
        print("  Press Ctrl+C to stop the server and close the link.")
        print("="*60 + "\n")

        # Keep running
        streamlit_process.wait()

    except Exception as e:
        print(f"\n❌  Could not create ngrok tunnel: {e}")
        print("\n  Alternative — use localtunnel instead:")
        print("  1. Install Node.js from https://nodejs.org")
        print("  2. Run: npx localtunnel --port 8501")
        print("\n  Or access locally at: http://localhost:8501")
        print("\n  The app is still running at http://localhost:8501\n")
        streamlit_process.wait()


if __name__ == "__main__":
    main()
