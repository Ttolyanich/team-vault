#!/bin/sh
set -eu
python manage.py migrate --noinput
python manage.py bootstrap_admin
python manage.py collectstatic --noinput --verbosity 0
exec "$@"
