#!/bin/sh

if [ "${DATABASE:-}" = "postgres" ]; then
  /app/scripts/wait_db.sh
fi

# if DB is ready then run migrations
/app/.venv/bin/python manage.py migrate --noinput
/app/.venv/bin/python manage.py collectstatic --noinput

exec "$@"
