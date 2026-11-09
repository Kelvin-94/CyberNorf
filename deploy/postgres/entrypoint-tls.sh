#!/bin/sh
# Generates a self-signed certificate for the PostgreSQL listener, then hands off
# to the image's normal entrypoint.
#
# Why this exists: the application refuses to start in production when its
# DATABASE_URL names a non-loopback host without TLS, so the bundled database
# has to speak TLS or the console cannot boot with it. The certificate is
# created once and lives in its own volume, so restarts and upgrades keep using
# the same identity.
#
# The same volume is mounted read-only into the app and migration containers,
# and DATABASE_URL points `sslrootcert` at the certificate. The client therefore
# verifies the server (sslmode=verify-full) instead of accepting whatever
# certificate is presented; node-postgres treats `sslmode=require` as
# verify-full in current releases, so the CA has to be reachable.
#
# For a managed database outside this stack, replace this with the provider's CA
# bundle: point sslrootcert at that file and remove the database-tls mount.

set -eu

TLS_DIR="${CYBERNORF_TLS_DIR:-/var/lib/postgresql/tls}"

mkdir -p "$TLS_DIR"

if [ ! -s "$TLS_DIR/server.crt" ] || [ ! -s "$TLS_DIR/server.key" ]; then
  echo "entrypoint-tls: generating a self-signed certificate in $TLS_DIR" >&2
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$TLS_DIR/server.key" \
    -out "$TLS_DIR/server.crt" \
    -subj "/CN=cybernorf-database" \
    -addext "subjectAltName=DNS:database,DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
fi

# PostgreSQL refuses to start when the key is readable by anyone else.
chown -R postgres:postgres "$TLS_DIR"
chmod 600 "$TLS_DIR/server.key"
chmod 644 "$TLS_DIR/server.crt"

exec /usr/local/bin/docker-entrypoint.sh "$@"
