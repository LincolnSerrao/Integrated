#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
python -m venv .venv-ml
source .venv-ml/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-ml.txt

echo "Backend virtual environment created at .venv-ml"
