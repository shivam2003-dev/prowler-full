#!/bin/sh
# Run API tests inside the local dev stack: ./api/run-tests-local.sh [pytest args]
# The dev container's env targets the running app (devel settings, non-owner DB
# role, RS256 keys from .env); tests need the testing settings instead.
cd "$(dirname "$0")/.." || exit 1
exec docker compose -f docker-compose-dev.yml -f docker-compose.local.yml exec -T \
  -e DJANGO_SETTINGS_MODULE=config.django.testing \
  -e POSTGRES_USER=prowler_admin -e POSTGRES_PASSWORD=postgres \
  -e DJANGO_TOKEN_SIGNING_KEY=insecure-testing-jwt-signing-key-do-not-use-in-prod \
  api-dev sh -c 'cd /home/prowler/backend && uv run pytest -p no:cacheprovider "$@"' sh "$@"
