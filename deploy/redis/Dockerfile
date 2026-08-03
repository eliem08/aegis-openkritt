ARG REDIS_IMAGE
FROM ${REDIS_IMAGE}
COPY deploy/redis/secure-entrypoint.sh /usr/local/bin/aegis-redis-entrypoint
RUN chmod 0755 /usr/local/bin/aegis-redis-entrypoint
ENTRYPOINT ["aegis-redis-entrypoint"]
