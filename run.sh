#!/bin/bash
# Launch the Double Ratchet PQC Benchmarking Suite with liboqs support.
# This script sets the dynamic library path so oqs-python can find liboqs.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export DYLD_LIBRARY_PATH="${SCRIPT_DIR}/_build/oqs_install/lib:${DYLD_LIBRARY_PATH:-}"

exec "${SCRIPT_DIR}/.venv/bin/python3" "${SCRIPT_DIR}/app.py" "$@"
