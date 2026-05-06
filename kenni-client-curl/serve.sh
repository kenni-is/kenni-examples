#!/usr/bin/env bash
# Tiny static-file server for the redirect landing page. Run this in one
# terminal; the numbered step scripts in another. Default port 8000.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PORT=${PORT:-8000}
cd "$SCRIPT_DIR/static"
echo "Serving $PWD on http://localhost:$PORT  (Ctrl-C to stop)"
exec python3 -m http.server "$PORT"
