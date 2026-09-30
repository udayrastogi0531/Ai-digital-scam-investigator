#!/bin/sh
# Apply database migrations, then start the process.
#
# This is the single documented initialization path for a fresh deployment:
# `alembic upgrade head` runs from the same DATABASE_URL the app uses.  It is
# idempotent — on an already-migrated database it is a no-op — so it is safe on
# every container start.
set -e

echo "Applying database migrations (alembic upgrade head)…"
alembic upgrade head

echo "Starting: $*"
exec "$@"
