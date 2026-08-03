#!/bin/sh
set -eu

install -d -m 0700 -o postgres -g postgres /run/aegis-postgres-tls
install -m 0600 -o postgres -g postgres /run/secrets/postgres_server_key /run/aegis-postgres-tls/server.key
install -m 0644 -o postgres -g postgres /run/secrets/postgres_server_cert /run/aegis-postgres-tls/server.crt
install -m 0644 -o postgres -g postgres /run/secrets/postgres_ca /run/aegis-postgres-tls/ca.crt

exec docker-entrypoint.sh "$@" \
  -c ssl=on \
  -c ssl_cert_file=/run/aegis-postgres-tls/server.crt \
  -c ssl_key_file=/run/aegis-postgres-tls/server.key \
  -c ssl_ca_file=/run/aegis-postgres-tls/ca.crt \
  -c password_encryption=scram-sha-256 \
  -c listen_addresses='*'
