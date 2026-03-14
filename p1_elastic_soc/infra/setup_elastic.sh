#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${REPO_ROOT}/.env"
ES_VERSION="${ES_VERSION:-8.11.0}"
ES_PORT="${ES_PORT:-9200}"
ES_CONTAINER_NAME="home-soc-elastic"

# Load existing .env if present
if [ -f "${ENV_FILE}" ]; then
    source "${ENV_FILE}" 2>/dev/null || true
fi

ELASTIC_PASSWORD="${ELASTIC_PASSWORD:-$(openssl rand -base64 24 | tr -d '/+=' | head -c 20)}"

echo "[*] Checking Elasticsearch availability..."
if curl -sk "https://localhost:${ES_PORT}" -u "elastic:${ELASTIC_PASSWORD}" --max-time 5 | grep -q "cluster_name"; then
    echo "[✓] Elasticsearch already running."
else
    echo "[*] Starting Elasticsearch ${ES_VERSION} in Docker..."

    # Stop existing container if present
    docker rm -f "${ES_CONTAINER_NAME}" 2>/dev/null || true

    # NOTE: TLS is disabled (xpack.security.http.ssl.enabled=false) for local dev convenience.
    # Do NOT use this configuration in production environments.
    docker run -d \
        --name "${ES_CONTAINER_NAME}" \
        -p "${ES_PORT}:9200" \
        -e "discovery.type=single-node" \
        -e "xpack.security.enabled=true" \
        -e "ELASTIC_PASSWORD=${ELASTIC_PASSWORD}" \
        -e "xpack.security.http.ssl.enabled=false" \
        "docker.elastic.co/elasticsearch/elasticsearch:${ES_VERSION}"

    echo "[*] Waiting for Elasticsearch to be ready (up to 120s)..."
    for i in $(seq 1 24); do
        if curl -sk "http://localhost:${ES_PORT}" -u "elastic:${ELASTIC_PASSWORD}" --max-time 5 | grep -q "cluster_name"; then
            echo "[✓] Elasticsearch ready."
            break
        fi
        echo "    Waiting... (${i}/24)"
        sleep 5
    done
fi

# Write credentials to .env
echo "[*] Writing credentials to ${ENV_FILE}..."
touch "${ENV_FILE}"
chmod 600 "${ENV_FILE}"

# Update or add ELASTIC_PASSWORD
if grep -q "^ELASTIC_PASSWORD=" "${ENV_FILE}"; then
    sed -i "s|^ELASTIC_PASSWORD=.*|ELASTIC_PASSWORD=${ELASTIC_PASSWORD}|" "${ENV_FILE}"
else
    echo "ELASTIC_PASSWORD=${ELASTIC_PASSWORD}" >> "${ENV_FILE}"
fi

# Add other defaults if not present
grep -q "^ELASTIC_HOST=" "${ENV_FILE}" || echo "ELASTIC_HOST=http://localhost:${ES_PORT}" >> "${ENV_FILE}"
grep -q "^ELASTIC_USER=" "${ENV_FILE}" || echo "ELASTIC_USER=elastic" >> "${ENV_FILE}"
grep -q "^ELASTIC_VERIFY_TLS=" "${ENV_FILE}" || echo "ELASTIC_VERIFY_TLS=false" >> "${ENV_FILE}"

chmod 600 "${ENV_FILE}"
echo "[✓] Credentials written to ${ENV_FILE} (mode 600)."

# Create required indices
echo "[*] Creating required indices..."
ES_BASE="http://localhost:${ES_PORT}"
AUTH="elastic:${ELASTIC_PASSWORD}"

for index in phishing-verdicts soar-cases soar-audit; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" -u "${AUTH}" "${ES_BASE}/${index}")
    if [ "${STATUS}" = "200" ]; then
        echo "    [✓] Index '${index}' already exists."
    else
        curl -sk -X PUT -u "${AUTH}" "${ES_BASE}/${index}" \
            -H "Content-Type: application/json" \
            -d '{"settings":{"number_of_shards":1,"number_of_replicas":0}}' | grep -q '"acknowledged":true' \
            && echo "    [✓] Created index '${index}'." \
            || echo "    [!] Failed to create index '${index}'."
    fi
done

echo "[✓] Elasticsearch setup complete."
