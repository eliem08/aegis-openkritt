ARG POSTGRES_IMAGE
FROM ${POSTGRES_IMAGE}
COPY deploy/postgres/secure-entrypoint.sh /usr/local/bin/aegis-pg-entrypoint
RUN chmod 0755 /usr/local/bin/aegis-pg-entrypoint
ENTRYPOINT ["aegis-pg-entrypoint"]
CMD ["postgres"]
