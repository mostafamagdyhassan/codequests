FROM postgres:15

# Copy custom config files
COPY pg_hba.conf /etc/postgresql/pg_hba.conf
COPY init.sql /docker-entrypoint-initdb.d/

# Point Postgres to use the custom pg_hba.conf
CMD ["postgres", "-c", "hba_file=/etc/postgresql/pg_hba.conf"]
