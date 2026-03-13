import os

from app import app

if __name__ == "__main__":
    # Render (and many PaaS providers) set the port via the PORT env var.
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
