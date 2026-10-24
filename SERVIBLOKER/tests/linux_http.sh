#!/usr/bin/env bash
# Ejecuta HTTP real en un namespace sin interfaces externas.
set -euo pipefail
[ "$(id -u)" -eq 0 ] && [ "$(uname -s)" = Linux ] || { echo 'Necesita Linux root'; exit 2; }
python_bin=${PYTHON:-python3}
base=$(cd "$(dirname "$0")" && pwd)
unshare --net -- /bin/sh -c 'ip link set lo up; exec "$1" "$2"' sh "$python_bin" "$base/test_http_transport.py"
