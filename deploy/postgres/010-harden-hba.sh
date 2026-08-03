#!/bin/sh
set -eu

# The official image needs local trust while it creates POSTGRES_USER and
# POSTGRES_DB. Before the temporary bootstrap server stops, replace every local
# trust rule so the real server accepts only password-authenticated clients.
sed -i -E 's/^(local[[:space:]]+.*[[:space:]]+)trust$/\1scram-sha-256/' "$PGDATA/pg_hba.conf"
if grep -Eq '^local[[:space:]]+.*[[:space:]]+trust$' "$PGDATA/pg_hba.conf"; then
  echo "failed to remove PostgreSQL local trust rule" >&2
  exit 1
fi
