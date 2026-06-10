#!/bin/sh
# provision_client.sh
# Usage: ./provision_client.sh <client_name> <app_port> <db_port> [gemini_api_key]

if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <client_name> <app_port> <db_port> [gemini_api_key]"
    exit 1
fi

# Sanitize client name to lowercase alphanumeric
CLIENT_NAME=$(echo "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')
APP_PORT=$2
DB_PORT=$3
GEMINI_API_KEY=$4

CLIENT_DIR="/opt/quantum-rap-clients/$CLIENT_NAME"
mkdir -p "$CLIENT_DIR"

cat <<EOF > "$CLIENT_DIR/docker-compose.yml"
version: '3.8'

services:
  db:
    image: postgres:15-alpine
    container_name: quarkshield-db-${CLIENT_NAME}
    restart: always
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: quarkshield_${CLIENT_NAME}
    ports:
      - '127.0.0.1:${DB_PORT}:5432'
      - '172.17.0.1:${DB_PORT}:5432'
    volumes:
      - pg_data_${CLIENT_NAME}:/var/lib/postgresql/data

  app:
    image: quantum-rap-app:latest
    container_name: quarkshield-app-${CLIENT_NAME}
    restart: always
    ports:
      - '${APP_PORT}:5000'
    depends_on:
      - db
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      - PORT=5000
      - DB_USER=postgres
      - DB_PASSWORD=postgres
      - DB_HOST=db
      - DB_PORT=5432
      - DB_DATABASE=quarkshield_${CLIENT_NAME}
      - GEMINI_API_KEY=${GEMINI_API_KEY}
      - NODE_ENV=production
      - SMTP_HOST=\${SMTP_HOST:-host.docker.internal}
      - SMTP_PORT=\${SMTP_PORT:-1025}
      - SMTP_SECURE=\${SMTP_SECURE:-false}
      - SMTP_USER=\${SMTP_USER:-}
      - SMTP_PASSWORD=\${SMTP_PASSWORD:-}
      - SMTP_FROM=\${SMTP_FROM:-support@quarkshield.services}

volumes:
  pg_data_${CLIENT_NAME}:
    driver: local
EOF

echo "Provisioning isolated stack for client '$CLIENT_NAME'..."
cd "$CLIENT_DIR"
docker compose up -d || exit 1

echo "--------------------------------------------------------"
echo "✓ Success! Client '$CLIENT_NAME' is provisioned."
echo "- App URL: http://quarkshield.services:$APP_PORT"
echo "- Database Port: $DB_PORT"
echo "- Data directory: $CLIENT_DIR"
echo "--------------------------------------------------------"
