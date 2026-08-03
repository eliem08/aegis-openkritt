#!/bin/sh
set -eu

install -d -m 0700 -o redis -g redis /run/aegis-redis
password="$(cat /run/secrets/redis_password)"
if [ -z "$password" ]; then
  echo "redis_password is empty" >&2
  exit 1
fi
cat > /run/aegis-redis/redis.conf <<EOF
bind 0.0.0.0
protected-mode yes
port 6379
requirepass $password
appendonly yes
appendfsync everysec
save 900 1
maxmemory 256mb
maxmemory-policy noeviction
dir /data
EOF
unset password
chown redis:redis /run/aegis-redis/redis.conf
chmod 0600 /run/aegis-redis/redis.conf
exec su-exec redis redis-server /run/aegis-redis/redis.conf
