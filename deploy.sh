#!/bin/bash
# Deploy FabricSRE to the runtime host (dns02): code, venv, database role, schema. Secrets stay in ~/fabricsre/.env on the host.
set -euo pipefail
HOST="${1:-dns02}"
rsync -a --delete --exclude .venv --exclude __pycache__ --exclude .env "$(dirname "$0")/" "$HOST:~/fabricsre/"
ssh "$HOST" 'set -e; cd ~/fabricsre
  [ -d .venv ] || python3 -m venv .venv
  .venv/bin/pip install -q --upgrade pip
  .venv/bin/pip install -q -e ".[dev]"
  # database: role fabricsre owning db fabricsre, password from .env (FABRICSRE_DB_URL)
  if [ -f .env ]; then set -a; . ./.env; set +a; fi
  PW=$(python3 -c "import os,urllib.parse as u; p=u.urlparse(os.environ.get(\"FABRICSRE_DB_URL\",\"\")); print(p.password or \"\")")
  sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='"'"'fabricsre'"'"'" | grep -q 1 || sudo -u postgres psql -c "CREATE ROLE fabricsre LOGIN PASSWORD '"'"'$PW'"'"'"
  sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='"'"'fabricsre'"'"'" | grep -q 1 || sudo -u postgres psql -c "CREATE DATABASE fabricsre OWNER fabricsre"
  .venv/bin/fabricsre init-db
  echo "deployed: $(.venv/bin/fabricsre version)"'
