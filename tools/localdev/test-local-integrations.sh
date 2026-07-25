#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/../.." && pwd)
PROJECT="netbird-local-integrations-test-$$"
NETWORK="${PROJECT}-network"
POSTGRES_CONTAINER="${PROJECT}-postgres"
LDAP_CONTAINER="${PROJECT}-openldap"
GO_IMAGE="${DEV_GO_IMAGE:-golang:1.25.12}"
GO_MOD_VOLUME="${DEV_GO_MOD_VOLUME:-netbird-dev-go-mod}"
GO_BUILD_VOLUME="${DEV_GO_BUILD_VOLUME:-netbird-dev-go-build}"

cleanup() {
  docker rm -f "$POSTGRES_CONTAINER" "$LDAP_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
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
docker network create "$NETWORK" >/dev/null

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
  postgres:17-alpine >/dev/null

docker run -d \
  --name "$LDAP_CONTAINER" \
  --network "$NETWORK" \
  --network-alias openldap \
  --security-opt no-new-privileges:true \
  --tmpfs /var/lib/ldap \
  --tmpfs /etc/ldap/slapd.d \
  -e LDAP_ORGANISATION='NetBird Test' \
  -e LDAP_DOMAIN=example.org \
  -e LDAP_BASE_DN=dc=example,dc=org \
  -e LDAP_ADMIN_PASSWORD=netbird_test_password \
  -e LDAP_TLS=false \
  -v "${REPO_ROOT}/deploy/ldap-init.ldif:/container/service/slapd/assets/config/bootstrap/ldif/custom/50-init.ldif:ro" \
  --health-cmd 'ldapsearch -x -H ldap://127.0.0.1 -b dc=example,dc=org -D cn=admin,dc=example,dc=org -w netbird_test_password >/dev/null' \
  --health-interval 2s \
  --health-timeout 5s \
  --health-retries 30 \
  osixia/openldap:1.5.0 --copy-service >/dev/null

wait_healthy "$POSTGRES_CONTAINER"
wait_healthy "$LDAP_CONTAINER"

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
