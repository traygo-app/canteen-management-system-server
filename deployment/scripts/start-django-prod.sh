#!/bin/bash

set -o errexit
set -o pipefail
set -o nounset

exec opentelemetry-instrument gunicorn --log-level debug config.wsgi:application --bind 0.0.0.0:8000 --chdir=/app
