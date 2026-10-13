"""Start Placement Sahaay.

    python run.py            # HTTPS on https://127.0.0.1:8443 (self-signed dev certificate)
    python run.py --http     # plain HTTP on http://127.0.0.1:5000 (local development only)

Production: run behind a TLS-terminating reverse proxy with a WSGI server,
e.g. `waitress-serve --host 127.0.0.1 --port 8000 --call app:create_app`.
"""
import os
import sys
from pathlib import Path

if "--http" in sys.argv:
    os.environ["PG_HTTPS"] = "0"

from app import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    if app.config["HTTPS"]:
        inst = Path(app.config["INSTANCE_DIR"])
        cert, key = inst / "dev-cert.pem", inst / "dev-key.pem"
        if not cert.exists():
            from scripts.gen_cert import generate
            generate(cert, key)
        app.run(host="127.0.0.1", port=8443, ssl_context=(str(cert), str(key)), debug=False)
    else:
        port = os.environ.get("PORT", "5000")
        if "--port" in sys.argv:
            port = sys.argv[sys.argv.index("--port") + 1]
        app.run(host="127.0.0.1", port=int(port), debug=False)
