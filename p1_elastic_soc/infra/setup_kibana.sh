#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${REPO_ROOT}/.env"
KIBANA_VERSION="${KIBANA_VERSION:-8.11.0}"
KIBANA_PORT="${KIBANA_PORT:-5601}"
KIBANA_CONTAINER_NAME="home-soc-kibana"
ES_HOST="${ELASTIC_HOST:-http://localhost:9200}"

# Load existing .env if present
if [ -f "${ENV_FILE}" ]; then
    source "${ENV_FILE}" 2>/dev/null || true
fi

ELASTIC_PASSWORD="${ELASTIC_PASSWORD:-changeme}"
KIBANA_SERVICETOKEN="${KIBANA_SERVICE_TOKEN:-}"

if [ -z "${KIBANA_SERVICE_TOKEN}" ]; then
    echo "[!] KIBANA_SERVICE_TOKEN is not set. Create one with:"
    echo "    curl -u elastic:<pass> -X POST \"${ES_HOST}/_security/service/elastic/kibana/credential/token/<name>?pretty\""
    exit 1
fi


echo "[*] Checking Kibana availability..."
if curl -sk "http://localhost:${KIBANA_PORT}/api/status" --max-time 5 | grep -q "available"; then
    echo "[✓] Kibana already running."
else
    echo "[*] Starting Kibana ${KIBANA_VERSION} in Docker..."

    # Get ES container IP or use host network
    ES_CONTAINER_IP=$(docker inspect home-soc-elastic --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null || echo "")
    ES_INTERNAL_HOST="${ES_CONTAINER_IP:+http://${ES_CONTAINER_IP}:9200}"
    ES_INTERNAL_HOST="${ES_INTERNAL_HOST:-${ES_HOST}}"

    docker rm -f "${KIBANA_CONTAINER_NAME}" 2>/dev/null || true

    docker run -d \
        --name "${KIBANA_CONTAINER_NAME}" \
        --link home-soc-elastic:elasticsearch \
        -p "${KIBANA_PORT}:5601" \
        -e "ELASTICSEARCH_HOSTS=${ES_INTERNAL_HOST}" \
        -e "ELASTICSEARCH_SERVICEACCOUNTTOKEN=${KIBANA_SERVICE_TOKEN}" \
        -e "XPACK_SECURITY_ENCRYPTIONKEY=${KIBANA_SECURITY_ENCRYPTION_KEY}" \
	-e "XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=${KIBANA_ENCRYPTEDSAVEDOBJECTS_ENCRYPTION_KEY}" \
	-e "XPACK_REPORTING_ENCRYPTIONKEY=${KIBANA_REPORTING_ENCRYPTION_KEY}" \
        "docker.elastic.co/kibana/kibana:${KIBANA_VERSION}"

    echo "[*] Waiting for Kibana to be ready (up to 180s)..."
    for i in $(seq 1 36); do
        if curl -sk "http://localhost:${KIBANA_PORT}/api/status" --max-time 5 | grep -q "available"; then
            echo "[✓] Kibana ready."
            break
        fi
        echo "    Waiting... (${i}/36)"
        sleep 5
    done
fi

# Write Kibana host to .env
touch "${ENV_FILE}"
chmod 600 "${ENV_FILE}"

if grep -q "^KIBANA_HOST=" "${ENV_FILE}"; then
    sed -i "s|^KIBANA_HOST=.*|KIBANA_HOST=http://localhost:${KIBANA_PORT}|" "${ENV_FILE}"
else
    echo "KIBANA_HOST=http://localhost:${KIBANA_PORT}" >> "${ENV_FILE}"
fi

chmod 600 "${ENV_FILE}"
echo "[✓] Kibana host written to ${ENV_FILE}."
echo "[✓] Kibana setup complete."
