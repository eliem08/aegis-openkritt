ARG POSTGRES_IMAGE
FROM ${POSTGRES_IMAGE}
COPY deploy/postgres/secure-entrypoint.sh /usr/local/bin/aegis-pg-entrypoint
COPY deploy/postgres/010-harden-hba.sh /docker-entrypoint-initdb.d/010-harden-hba.sh
RUN chmod 0755 /usr/local/bin/aegis-pg-entrypoint /docker-entrypoint-initdb.d/010-harden-hba.sh
ENTRYPOINT ["aegis-pg-entrypoint"]
CMD ["postgres"]
