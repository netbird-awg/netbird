#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
PROJECT="netbird-local-integrations-test-$$"
NETWORK="${PROJECT}-network"
POSTGRES_CONTAINER="${PROJECT}-postgres"
LDAP_CONTAINER="${PROJECT}-openldap"
LDAP_IMAGE="${PROJECT}-openldap:local"
LDAP_TLS_VOLUME="${PROJECT}-ldap-tls"
GO_IMAGE="${DEV_GO_IMAGE:-golang:1.25.12@sha256:9006890ecba0a168034d99516084099ae3114d9f2b7d6572c77f2dde57ebc980}"
GO_MOD_VOLUME="${DEV_GO_MOD_VOLUME:-netbird-dev-go-mod}"
GO_BUILD_VOLUME="${DEV_GO_BUILD_VOLUME:-netbird-dev-go-build}"

cleanup() {
  docker rm -f "$POSTGRES_CONTAINER" "$LDAP_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
  docker volume rm "$LDAP_TLS_VOLUME" >/dev/null 2>&1 || true
  docker image rm "$LDAP_IMAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

wait_healthy() {
  local container="$1"
  local status

  for _ in $(seq 1 90); do
    status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container" 2>/dev/null || true)
    case "$status" in
      healthy|running)
        return 0
        ;;
      unhealthy|exited|dead)
        docker logs --tail=100 "$container" >&2
        return 1
        ;;
    esac
    sleep 2
  done

  echo "Timed out waiting for ${container}." >&2
  docker logs --tail=100 "$container" >&2
  return 1
}

docker volume create "$GO_MOD_VOLUME" >/dev/null
docker volume create "$GO_BUILD_VOLUME" >/dev/null
docker volume create "$LDAP_TLS_VOLUME" >/dev/null
docker network create "$NETWORK" >/dev/null

docker build \
  -t "$LDAP_IMAGE" \
  -f "${REPO_ROOT}/deploy/openldap/Dockerfile" \
  "${REPO_ROOT}/deploy/openldap" >/dev/null

docker run --rm \
  --entrypoint sh \
  -v "${LDAP_TLS_VOLUME}:/tls" \
  alpine/openssl:3.5.4@sha256:42c7389ef077aed0eb4e96d0abbd094083d701bbaff1313073b061c0c9cd8278 -ec '
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout /tls/ca.key -out /tls/ca.crt -days 1 -sha256 \
      -subj "/CN=NetBird Test LDAP CA" >/dev/null 2>&1
    openssl req -newkey rsa:2048 -nodes \
      -keyout /tls/ldap.key -out /tmp/ldap.csr \
      -subj "/CN=openldap" >/dev/null 2>&1
    printf "%s\n" \
      "subjectAltName=DNS:openldap" \
      "basicConstraints=critical,CA:FALSE" \
      "keyUsage=critical,digitalSignature,keyEncipherment" \
      "extendedKeyUsage=serverAuth" >/tmp/ldap-ext.cnf
    openssl x509 -req -in /tmp/ldap.csr \
      -CA /tls/ca.crt -CAkey /tls/ca.key -CAcreateserial \
      -out /tls/ldap.crt -days 1 -sha256 -extfile /tmp/ldap-ext.cnf >/dev/null 2>&1
    chmod 600 /tls/ca.key /tls/ldap.key
    chmod 644 /tls/ca.crt /tls/ldap.crt
  '

docker run -d \
  --name "$POSTGRES_CONTAINER" \
  --network "$NETWORK" \
  --network-alias postgres \
  --security-opt no-new-privileges:true \
  --tmpfs /var/lib/postgresql/data \
  -e POSTGRES_USER=netbird_test \
  -e POSTGRES_PASSWORD=netbird_test_password \
  -e POSTGRES_DB=netbird_test \
  --health-cmd 'pg_isready -U netbird_test -d netbird_test' \
  --health-interval 2s \
  --health-timeout 3s \
  --health-retries 30 \
  postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193 >/dev/null

docker run -d \
  --name "$LDAP_CONTAINER" \
  --network "$NETWORK" \
  --network-alias openldap \
  --security-opt no-new-privileges:true \
  --cap-drop ALL \
  --cap-add CHOWN \
  --cap-add DAC_OVERRIDE \
  --cap-add FOWNER \
  --cap-add SETGID \
  --cap-add SETUID \
  --read-only \
  --tmpfs /var/lib/ldap \
  --tmpfs /run:rw,noexec,nosuid,size=16m \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -e LDAP_BASE_DN=dc=example,dc=org \
  -e LDAP_ADMIN_PASSWORD=netbird_test_password \
  -e LDAP_LISTEN_URIS='ldap:/// ldapi:///' \
  -e LDAP_TLS_CERT_FILE=/cert-seed/ldap.crt \
  -e LDAP_TLS_KEY_FILE=/cert-seed/ldap.key \
  -e LDAP_TLS_CA_FILE=/cert-seed/ca.crt \
  -v "${REPO_ROOT}/deploy/ldap-init.ldif:/bootstrap/custom.ldif:ro" \
  -v "${LDAP_TLS_VOLUME}:/cert-seed:ro" \
  --health-cmd 'ldapsearch -x -H ldap://127.0.0.1 -b dc=example,dc=org -D cn=admin,dc=example,dc=org -w netbird_test_password >/dev/null' \
  --health-interval 2s \
  --health-timeout 5s \
  --health-retries 30 \
  "$LDAP_IMAGE" >/dev/null

wait_healthy "$POSTGRES_CONTAINER"
wait_healthy "$LDAP_CONTAINER"
docker exec "$LDAP_CONTAINER" sh -ec '
  slapd_pid=$(pidof slapd)
  test -n "$slapd_pid"
  test "$(stat -c %u "/proc/$slapd_pid")" = "$(id -u openldap)"
  grep -q "^CapEff:[[:space:]]*0000000000000000$" "/proc/$slapd_pid/status"
'

docker run --rm \
  --network "$NETWORK" \
  --security-opt no-new-privileges:true \
  -e NETBIRD_STORE_ENGINE=postgres \
  -e 'NB_STORE_ENGINE_POSTGRES_DSN=host=postgres port=5432 user=netbird_test password=netbird_test_password dbname=netbird_test sslmode=disable TimeZone=UTC' \
  -e NB_RUN_LOCAL_LDAP_INTEGRATION_TESTS=true \
  -e NB_LOCAL_LDAP_TEST_PASSWORD=netbird_test_password \
	-e NETBIRD_LDAP_TEST_HOST=openldap:389 \
  -v "${REPO_ROOT}:/workspace:ro" \
  -v "${GO_MOD_VOLUME}:/go/pkg/mod" \
  -v "${GO_BUILD_VOLUME}:/root/.cache/go-build" \
  -w /workspace \
  "$GO_IMAGE" \
  go test -count=1 -run 'LocalLDAPSync|LDAPDirectoryIntegration' \
    ./management/server/store \
    ./management/server/localintegrations/ldapsync \
    ./idp/dex
