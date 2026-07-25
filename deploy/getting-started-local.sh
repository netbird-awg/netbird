#!/bin/bash

set -euo pipefail

# NetBird Getting Started with Embedded IdP (Dex)
# This script sets up NetBird with the embedded Dex identity provider
# No separate Dex container or reverse proxy needed - IdP is built into management server

# Sed pattern to strip base64 padding characters
SED_STRIP_PADDING='s/=//g'

# Constants for repeated string literals
readonly MSG_STARTING_SERVICES="\nStarting NetBird services\n"
readonly MSG_DONE="\nDone!\n"
readonly MSG_NEXT_STEPS="Next steps:"
readonly MSG_SEPARATOR="=========================================="

############################################
# Utility Functions
############################################

check_docker_sock_perms() {
  local sock="${DOCKER_HOST:-unix:///var/run/docker.sock}"
  sock="${sock#unix://}"

  if [[ ! -S "$sock" ]]; then
    return 0
  fi

  if [[ ! -r "$sock" ]] || [[ ! -w "$sock" ]]; then
    local group
    if [[ "${OSTYPE}" == "darwin"* ]]; then
      group="$(stat -f '%Sg' "$sock")"
    else
      group="$(stat -c '%G' "$sock")"
    fi

    echo "Cannot access Docker socket: $sock" > /dev/stderr
    echo "" > /dev/stderr
    echo "Socket permissions:" > /dev/stderr
    ls -l "$sock" > /dev/stderr
    echo "" > /dev/stderr

    if [[ "$group" == "docker" ]]; then
      echo "Your user may need to be added to the '$group' group:" > /dev/stderr
      echo "  sudo usermod -aG $group \"$USER\"" > /dev/stderr
      echo "Then log out and back in, or run this for the current shell:" > /dev/stderr
      echo "  newgrp $group" > /dev/stderr
      echo "Note: newgrp is temporary; usermod is the permanent group change." > /dev/stderr
    else
      echo "The Docker socket is owned by the '$group' group, which is not the standard 'docker' group." > /dev/stderr
      echo "For safety, this script will not suggest adding your user to '$group'." > /dev/stderr
      echo "Instead, either run this script with appropriate privileges (for example, via sudo) or follow Docker's post-install steps to configure access via the 'docker' group:" > /dev/stderr
      echo "  https://docs.docker.com/engine/install/linux-postinstall/" > /dev/stderr
    fi

    exit 1
  fi
  return 0
}

check_docker_compose() {
  if command -v docker-compose &> /dev/null
  then
      echo "docker-compose"
      return
  fi
  if docker compose --help &> /dev/null
  then
      echo "docker compose"
      return
  fi

  echo "docker-compose is not installed or not in PATH. Please follow the steps from the official guide: https://docs.docker.com/engine/install/" > /dev/stderr
  exit 1
}

check_jq() {
  if ! command -v jq &> /dev/null
  then
    echo "jq is not installed or not in PATH, please install with your package manager. e.g. sudo apt install jq" > /dev/stderr
    exit 1
  fi
  return 0
}

get_main_ip_address() {
  if [[ "$OSTYPE" == "darwin"* ]]; then
    interface=$(route -n get default | grep 'interface:' | awk '{print $2}')
    ip_address=$(ifconfig "$interface" | grep 'inet ' | awk '{print $2}')
  else
    interface=$(ip route | grep default | awk '{print $5}' | head -n 1)
    ip_address=$(ip addr show "$interface" | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1)
  fi

  echo "$ip_address"
  return 0
}

check_nb_domain() {
  DOMAIN=$1
  if [[ "$DOMAIN-x" == "-x" ]]; then
    echo "The NETBIRD_DOMAIN variable cannot be empty." > /dev/stderr
    return 1
  fi

  if [[ "$DOMAIN" == "netbird.example.com" ]]; then
    echo "The NETBIRD_DOMAIN cannot be netbird.example.com" > /dev/stderr
    return 1
  fi
  return 0
}

read_nb_domain() {
  READ_NETBIRD_DOMAIN=""
  echo -n "Enter the domain you want to use for NetBird (e.g. netbird.my-domain.com): " > /dev/stderr
  read -r READ_NETBIRD_DOMAIN < /dev/tty
  if ! check_nb_domain "$READ_NETBIRD_DOMAIN"; then
    read_nb_domain
  fi
  echo "$READ_NETBIRD_DOMAIN"
  return 0
}

read_reverse_proxy_type() {
  echo "" > /dev/stderr
  echo "Which reverse proxy will you use?" > /dev/stderr
  echo "  [0] Traefik (recommended - automatic TLS, included in Docker Compose)" > /dev/stderr
  echo "  [1] Existing Traefik (labels for external Traefik instance)" > /dev/stderr
  echo "  [2] Nginx (generates config template)" > /dev/stderr
  echo "  [3] Nginx Proxy Manager (generates config + instructions)" > /dev/stderr
  echo "  [4] External Caddy (generates Caddyfile snippet)" > /dev/stderr
  echo "  [5] Other/Manual (displays setup documentation)" > /dev/stderr
  echo "" > /dev/stderr
  echo -n "Enter choice [0-5] (default: 0): " > /dev/stderr
  read -r CHOICE < /dev/tty

  if [[ -z "$CHOICE" ]]; then
    CHOICE="0"
  fi

  if [[ ! "$CHOICE" =~ ^[0-5]$ ]]; then
    echo "Invalid choice. Please enter a number between 0 and 5." > /dev/stderr
    read_reverse_proxy_type
    return
  fi

  echo "$CHOICE"
  return 0
}

read_traefik_network() {
  echo "" > /dev/stderr
  echo "If you have an existing Traefik instance, enter its external network name." > /dev/stderr
  echo -n "External network (leave empty to create 'netbird' network): " > /dev/stderr
  read -r NETWORK < /dev/tty
  echo "$NETWORK"
  return 0
}

read_traefik_entrypoint() {
  echo "" > /dev/stderr
  echo "Enter the name of your Traefik HTTPS entrypoint." > /dev/stderr
  echo -n "HTTPS entrypoint name (default: websecure): " > /dev/stderr
  read -r ENTRYPOINT < /dev/tty
  if [[ -z "$ENTRYPOINT" ]]; then
    ENTRYPOINT="websecure"
  fi
  echo "$ENTRYPOINT"
  return 0
}

read_traefik_certresolver() {
  echo "" > /dev/stderr
  echo "Enter the name of your Traefik certificate resolver (for automatic TLS)." > /dev/stderr
  echo "Leave empty if you handle TLS termination elsewhere or use a wildcard cert." > /dev/stderr
  echo -n "Certificate resolver name (e.g., letsencrypt): " > /dev/stderr
  read -r RESOLVER < /dev/tty
  echo "$RESOLVER"
  return 0
}

read_port_binding_preference() {
  echo "" > /dev/stderr
  echo "Should container ports be bound to localhost only (127.0.0.1)?" > /dev/stderr
  echo "Choose 'yes' if your reverse proxy runs on the same host (more secure)." > /dev/stderr
  echo -n "Bind to localhost only? [Y/n]: " > /dev/stderr
  read -r CHOICE < /dev/tty

  if [[ "$CHOICE" =~ ^[Nn]$ ]]; then
    echo "false"
  else
    echo "true"
  fi
  return 0
}

read_proxy_docker_network() {
  local proxy_name="$1"
  echo "" > /dev/stderr
  echo "Is ${proxy_name} running in Docker?" > /dev/stderr
  echo "If yes, enter the Docker network ${proxy_name} is on (NetBird will join it)." > /dev/stderr
  echo -n "Docker network (leave empty if not in Docker): " > /dev/stderr
  read -r NETWORK < /dev/tty
  echo "$NETWORK"
  return 0
}

read_enable_proxy() {
  echo "" > /dev/stderr
  echo "Do you want to enable the NetBird Proxy service?" > /dev/stderr
  echo "The proxy allows you to selectively expose internal NetBird network resources" > /dev/stderr
  echo "to the internet. You control which resources are exposed through the dashboard." > /dev/stderr
  echo -n "Enable proxy? [y/N]: " > /dev/stderr
  read -r CHOICE < /dev/tty

  if [[ "$CHOICE" =~ ^[Yy]$ ]]; then
    echo "true"
  else
    echo "false"
  fi
  return 0
}

read_enable_crowdsec() {
  echo "" > /dev/stderr
  echo "Do you want to enable CrowdSec IP reputation blocking?" > /dev/stderr
  echo "CrowdSec checks client IPs against a community threat intelligence database" > /dev/stderr
  echo "and blocks known malicious sources before they reach your services." > /dev/stderr
  echo "A local CrowdSec LAPI container will be added to your deployment." > /dev/stderr
  echo -n "Enable CrowdSec? [y/N]: " > /dev/stderr
  read -r CHOICE < /dev/tty

  if [[ "$CHOICE" =~ ^[Yy]$ ]]; then
    echo "true"
  else
    echo "false"
  fi
  return 0
}

read_traefik_acme_email() {
  echo "" > /dev/stderr
  echo "Enter your email for Let's Encrypt certificate notifications." > /dev/stderr
  echo -n "Email address: " > /dev/stderr
  read -r EMAIL < /dev/tty
  if [[ -z "$EMAIL" ]]; then
    echo "Email is required for Let's Encrypt." > /dev/stderr
    read_traefik_acme_email
    return
  fi
  echo "$EMAIL"
  return 0
}

get_bind_address() {
  if [[ "$BIND_LOCALHOST_ONLY" == "true" ]]; then
    echo "127.0.0.1"
  else
    echo "0.0.0.0"
  fi
  return 0
}

get_upstream_host() {
  # Always return 127.0.0.1 for health checks and upstream targets
  # Cannot use 0.0.0.0 as a connection target
  echo "127.0.0.1"
  return 0
}

wait_management_proxy() {
  local proxy_container="${1:-traefik}"
  local use_docker_logs=false
  set +e

  if [[ "$proxy_container" == "detect-traefik" ]]; then
    proxy_container=$(docker ps --format "{{.ID}}\t{{.Image}}\t{{.Ports}}" \
    | awk -F'\t' '$2 ~ /traefik/ && $3 ~ /:(80|443)->/ {print $1; exit}')

    if [[ -z "$proxy_container" ]]; then
      echo "Warning: could not auto-detect Traefik container, log output will be skipped on timeout." > /dev/stderr
    else
      use_docker_logs=true
    fi
  fi

  echo -n "Waiting for NetBird server to become ready"
  counter=1
  while true; do
    # Check the embedded IdP endpoint through the reverse proxy
    if curl -sk -f -o /dev/null "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/oauth2/.well-known/openid-configuration" 2>/dev/null; then
      break
    fi
    if [[ $counter -eq 60 ]]; then
      echo ""
      echo "Taking too long. Checking logs..."
      if [[ -n "$proxy_container" ]]; then
        if [[ "$use_docker_logs" == "true" ]]; then
          docker logs --tail=20 "$proxy_container"
        else
          $DOCKER_COMPOSE_COMMAND logs --tail=20 "$proxy_container"
        fi
      fi
      $DOCKER_COMPOSE_COMMAND logs --tail=20 netbird-server
    fi
    echo -n " ."
    sleep 2
    counter=$((counter + 1))
  done
  echo " done"
  set -e
  return 0
}

wait_management_direct() {
  set +e
  local upstream_host
  upstream_host=$(get_upstream_host)
  echo -n "Waiting for NetBird server to become ready"
  counter=1
  while true; do
    # Check the embedded IdP endpoint directly (no reverse proxy)
    if curl -sk -f -o /dev/null "http://${upstream_host}:${MANAGEMENT_HOST_PORT}/oauth2/.well-known/openid-configuration" 2>/dev/null; then
      break
    fi
    if [[ $counter -eq 60 ]]; then
      echo ""
      echo "Taking too long. Checking logs..."
      $DOCKER_COMPOSE_COMMAND logs --tail=20 netbird-server
    fi
    echo -n " ."
    sleep 2
    counter=$((counter + 1))
  done
  echo " done"
  set -e
  return 0
}

############################################
# Initialization and Configuration
############################################

initialize_default_values() {
  NETBIRD_PORT=80
  NETBIRD_HTTP_PROTOCOL="http"
  NETBIRD_RELAY_PROTO="rel"
  NETBIRD_RELAY_AUTH_SECRET=$(openssl rand -base64 32 | sed "$SED_STRIP_PADDING")
  # Note: DataStoreEncryptionKey must keep base64 padding (=) for Go's base64.StdEncoding
  DATASTORE_ENCRYPTION_KEY=$(openssl rand -base64 32)
  NETBIRD_STUN_PORT=3478

  # Docker images
  DASHBOARD_IMAGE=${DASHBOARD_IMAGE:-"netbirdio/dashboard:latest"}
  # Combined server replaces separate signal, relay, and management containers
  NETBIRD_SERVER_IMAGE=${NETBIRD_SERVER_IMAGE:-"netbirdio/netbird-server:latest"}
  NETBIRD_PROXY_IMAGE=${NETBIRD_PROXY_IMAGE:-"netbirdio/reverse-proxy:latest"}
  TRAEFIK_IMAGE=${TRAEFIK_IMAGE:-"traefik:v3.6"}
  CROWDSEC_IMAGE=${CROWDSEC_IMAGE:-"crowdsecurity/crowdsec:v1.7.7"}
  # Reverse proxy configuration
  REVERSE_PROXY_TYPE="0"
  TRAEFIK_EXTERNAL_NETWORK=""
  TRAEFIK_ENTRYPOINT="websecure"
  TRAEFIK_CERTRESOLVER=""
  TRAEFIK_ACME_EMAIL=""
  DASHBOARD_HOST_PORT="8080"
  MANAGEMENT_HOST_PORT="8081"  # Combined server port (management + signal + relay)
  BIND_LOCALHOST_ONLY="true"
  EXTERNAL_PROXY_NETWORK=""

  # Traefik static IP within the internal bridge network
  TRAEFIK_IP="172.30.0.10"

  # NetBird Proxy configuration
  ENABLE_PROXY="false"
  PROXY_TOKEN=""

  # CrowdSec configuration
  ENABLE_CROWDSEC="false"
  CROWDSEC_BOUNCER_KEY=""
  return 0
}

configure_domain() {
  if ! check_nb_domain "$NETBIRD_DOMAIN"; then
    NETBIRD_DOMAIN=$(read_nb_domain)
  fi

  if [[ "$NETBIRD_DOMAIN" == "use-ip" ]]; then
    NETBIRD_DOMAIN=$(get_main_ip_address)
    BASE_DOMAIN=$NETBIRD_DOMAIN
  else
    NETBIRD_PORT=443
    NETBIRD_HTTP_PROTOCOL="https"
    # shellcheck disable=SC2034 # consumed by generated deployment templates
    NETBIRD_RELAY_PROTO="rels"
    # shellcheck disable=SC2034 # consumed by generated deployment templates
    BASE_DOMAIN=$(echo "$NETBIRD_DOMAIN" | sed -E 's/^[^.]+\.//')
  fi
  return 0
}

apply_agent_network_preset() {
  # Agent-network turnkey install: built-in Traefik + NetBird Proxy with
  # NB_PROXY_PRIVATE=true, dashboard locked to agent-network-only mode.
  # Bypasses every reverse-proxy / proxy / CrowdSec prompt. The only
  # inputs we still need from the operator are the domain (handled by
  # configure_domain via NETBIRD_DOMAIN env var or interactive prompt)
  # and the ACME email — both honor env vars first and fall back to a
  # prompt only when unset. CrowdSec is intentionally off.
  REVERSE_PROXY_TYPE="0"
  ENABLE_PROXY="true"
  ENABLE_CROWDSEC="false"

  if [[ -n "${NETBIRD_LETSENCRYPT_EMAIL}" ]]; then
    TRAEFIK_ACME_EMAIL="${NETBIRD_LETSENCRYPT_EMAIL}"
  else
    TRAEFIK_ACME_EMAIL=$(read_traefik_acme_email)
  fi

  echo "" > /dev/stderr
  echo "Agent-network preset enabled (NETBIRD_AGENT_NETWORK=true):" > /dev/stderr
  echo "  - reverse proxy: built-in Traefik" > /dev/stderr
  echo "  - NetBird Proxy: enabled with NB_PROXY_PRIVATE=true" > /dev/stderr
  echo "  - server image: ${NETBIRD_SERVER_IMAGE}" > /dev/stderr
  echo "  - proxy image: ${NETBIRD_PROXY_IMAGE}" > /dev/stderr
  echo "  - dashboard: NETBIRD_AGENT_NETWORK_ONLY=true" > /dev/stderr
  echo "  - CrowdSec: disabled" > /dev/stderr
  echo "  - Let's Encrypt email: ${TRAEFIK_ACME_EMAIL}" > /dev/stderr
  echo "" > /dev/stderr
}

configure_reverse_proxy() {
  # Short-circuit: agent-network preset locks every reverse-proxy /
  # proxy / CrowdSec choice and bypasses the interactive prompts.
  if [[ "${NETBIRD_AGENT_NETWORK}" == "true" ]]; then
    apply_agent_network_preset
    return 0
  fi

  # Prompt for reverse proxy type
  REVERSE_PROXY_TYPE=$(read_reverse_proxy_type)

  # Handle built-in Traefik prompts (option 0)
  if [[ "$REVERSE_PROXY_TYPE" == "0" ]]; then
    TRAEFIK_ACME_EMAIL=$(read_traefik_acme_email)
    ENABLE_PROXY=$(read_enable_proxy)
    if [[ "$ENABLE_PROXY" == "true" ]]; then
      ENABLE_CROWDSEC=$(read_enable_crowdsec)
    fi
  fi

  # Handle external Traefik-specific prompts (option 1)
  if [[ "$REVERSE_PROXY_TYPE" == "1" ]]; then
    TRAEFIK_EXTERNAL_NETWORK=$(read_traefik_network)
    TRAEFIK_ENTRYPOINT=$(read_traefik_entrypoint)
    TRAEFIK_CERTRESOLVER=$(read_traefik_certresolver)
  fi

  # Handle port binding for external proxy options (2-5)
  if [[ "$REVERSE_PROXY_TYPE" -ge 2 ]]; then
    BIND_LOCALHOST_ONLY=$(read_port_binding_preference)
  fi

  # Handle Docker network prompts for external proxies (options 2-4)
  case "$REVERSE_PROXY_TYPE" in
    2) EXTERNAL_PROXY_NETWORK=$(read_proxy_docker_network "Nginx") ;;
    3) EXTERNAL_PROXY_NETWORK=$(read_proxy_docker_network "Nginx Proxy Manager") ;;
    4) EXTERNAL_PROXY_NETWORK=$(read_proxy_docker_network "Caddy") ;;
    *) ;; # No network prompt for other options
  esac
  return 0
}

check_existing_installation() {
  if [[ -f config.yaml ]]; then
    echo "Generated files already exist, if you want to reinitialize the environment, please remove them first."
    echo "You can use the following commands:"
    echo "  $DOCKER_COMPOSE_COMMAND down --volumes # to remove all containers and volumes"
    echo "  rm -f docker-compose.yml dashboard.env config.yaml proxy.env traefik-dynamic.yaml nginx-netbird.conf caddyfile-netbird.txt npm-advanced-config.txt && rm -rf crowdsec/"
    echo "Be aware that this will remove all data from the database, and you will have to reconfigure the dashboard."
    exit 1
  fi
  return 0
}

generate_configuration_files() {
  echo Rendering initial files...

  # Render docker-compose and proxy config based on selection
  case "$REVERSE_PROXY_TYPE" in
    0)
      render_docker_compose_traefik_builtin > docker-compose.yml
      if [[ "$ENABLE_PROXY" == "true" ]]; then
        # Create placeholder proxy.env so docker-compose can validate
        # This will be overwritten with the actual token after netbird-server starts
        echo "# Placeholder - will be updated with token after netbird-server starts" > proxy.env
        echo "NB_PROXY_TOKEN=placeholder" >> proxy.env
        # TCP ServersTransport for PROXY protocol v2 to the proxy backend
        render_traefik_dynamic > traefik-dynamic.yaml
        if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
          mkdir -p crowdsec
        fi
      fi
      ;;
    1)
      render_docker_compose_traefik > docker-compose.yml
      ;;
    2)
      render_docker_compose_exposed_ports > docker-compose.yml
      render_nginx_conf > nginx-netbird.conf
      ;;
    3)
      render_docker_compose_exposed_ports > docker-compose.yml
      render_npm_advanced_config > npm-advanced-config.txt
      ;;
    4)
      render_docker_compose_exposed_ports > docker-compose.yml
      render_external_caddyfile > caddyfile-netbird.txt
      ;;
    5)
      render_docker_compose_exposed_ports > docker-compose.yml
      ;;
    *)
      echo "Invalid reverse proxy type: $REVERSE_PROXY_TYPE" > /dev/stderr
      exit 1
      ;;
  esac

  # Common files for all configurations
  render_dashboard_env > dashboard.env
  render_combined_yaml > config.yaml
  return 0
}

start_services_and_show_instructions() {
  # For built-in Traefik, start containers immediately
  # For NPM, start containers first (NPM needs services running to create proxy)
  # For other external proxies, show instructions first and wait for user confirmation
  if [[ "$REVERSE_PROXY_TYPE" == "0" ]]; then
    # Built-in Traefik - two-phase startup if proxy is enabled
    echo -e "$MSG_STARTING_SERVICES"

    if [[ "$ENABLE_PROXY" == "true" ]]; then
      # Phase 1: Start core services (without proxy)
      local core_services="traefik dashboard netbird-server"
      if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
        core_services="$core_services crowdsec"
      fi
      echo "Starting core services..."
      # shellcheck disable=SC2086 # service names intentionally expand as separate compose arguments
      $DOCKER_COMPOSE_COMMAND up -d $core_services

      sleep 3
      wait_management_proxy traefik

      # Phase 2: Create proxy token and start proxy
      echo ""
      echo "Creating proxy access token..."
      # Use docker exec with bash to run the token command directly
      PROXY_TOKEN=$($DOCKER_COMPOSE_COMMAND exec -T netbird-server \
        /go/bin/netbird-server token create --name "default-proxy" --config /etc/netbird/config.yaml 2>/dev/null | grep "^Token:" | awk '{print $2}')

      if [[ -z "$PROXY_TOKEN" ]]; then
        echo "ERROR: Failed to create proxy token. Check netbird-server logs." > /dev/stderr
        $DOCKER_COMPOSE_COMMAND logs --tail=20 netbird-server
        exit 1
      fi

      echo "Proxy token created successfully."

      if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
        echo "Registering CrowdSec bouncer..."
        local cs_retries=0
        while ! $DOCKER_COMPOSE_COMMAND exec -T crowdsec cscli lapi status >/dev/null 2>&1; do
          cs_retries=$((cs_retries + 1))
          if [[ $cs_retries -ge 30 ]]; then
            echo "WARNING: CrowdSec did not become ready. Skipping CrowdSec setup." > /dev/stderr
            echo "You can register a bouncer manually later with:" > /dev/stderr
            echo "  docker exec netbird-crowdsec cscli bouncers add netbird-proxy -o raw" > /dev/stderr
            ENABLE_CROWDSEC="false"
            break
          fi
          sleep 2
        done

        if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
          CROWDSEC_BOUNCER_KEY=$($DOCKER_COMPOSE_COMMAND exec -T crowdsec \
            cscli bouncers add netbird-proxy -o raw 2>/dev/null)
          if [[ -z "$CROWDSEC_BOUNCER_KEY" ]]; then
            echo "WARNING: Failed to create CrowdSec bouncer key. Skipping CrowdSec setup." > /dev/stderr
            ENABLE_CROWDSEC="false"
          else
            echo "CrowdSec bouncer registered."
          fi
        fi
      fi

      render_proxy_env > proxy.env

      # Start proxy service
      echo "Starting proxy service..."
      $DOCKER_COMPOSE_COMMAND up -d proxy
    else
      # No proxy - start all services at once
      $DOCKER_COMPOSE_COMMAND up -d

      sleep 3
      wait_management_proxy traefik
    fi

    echo -e "$MSG_DONE"
    print_post_setup_instructions
  elif [[ "$REVERSE_PROXY_TYPE" == "1" ]]; then
    # External Traefik - start containers, then show instructions
    # Traefik discovers services via Docker labels, so containers must be running
    echo -e "$MSG_STARTING_SERVICES"
    $DOCKER_COMPOSE_COMMAND up -d

    sleep 3
    wait_management_proxy detect-traefik

    echo -e "$MSG_DONE"
    print_post_setup_instructions
    echo ""
    echo "NetBird containers are running. Once Traefik is connected, access the dashboard at:"
    echo "  $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN"
  elif [[ "$REVERSE_PROXY_TYPE" == "3" ]]; then
    # NPM - start containers first, then show instructions
    # NPM requires backend services to be running before creating proxy hosts
    echo -e "$MSG_STARTING_SERVICES"
    $DOCKER_COMPOSE_COMMAND up -d

    sleep 3
    wait_management_direct

    echo -e "$MSG_DONE"
    print_post_setup_instructions
    echo ""
    echo "NetBird containers are running. Configure NPM as shown above, then access:"
    echo "  $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN"
  else
    # External proxies (nginx, external Caddy, other) - need manual config first
    print_post_setup_instructions

    echo ""
    echo -n "Press Enter when your reverse proxy is configured (or Ctrl+C to exit)... "
    read -r < /dev/tty

    echo -e "$MSG_STARTING_SERVICES"
    $DOCKER_COMPOSE_COMMAND up -d

    sleep 3
    wait_management_direct

    echo -e "$MSG_DONE"
    echo "NetBird is now running. Access the dashboard at:"
    echo "  $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN"
  fi
  return 0
}

init_environment() {
  # Check if docker compose is installed using check_docker_compose function
  DOCKER_COMPOSE_COMMAND=$(check_docker_compose)
  check_docker_sock_perms

  initialize_default_values
  configure_domain
  configure_reverse_proxy

  check_jq

  check_existing_installation
  generate_configuration_files
  start_services_and_show_instructions
  return 0
}

############################################
# Configuration File Renderers
############################################

render_docker_compose_traefik_builtin() {
  # Generate proxy service section and Traefik dynamic config if enabled
  local proxy_service=""
  local proxy_volumes=""
  local crowdsec_service=""
  local crowdsec_volumes=""
  local traefik_file_provider=""
  local traefik_dynamic_volume=""
  if [[ "$ENABLE_PROXY" == "true" ]]; then
    traefik_file_provider='      - "--providers.file.filename=/etc/traefik/dynamic.yaml"'
    traefik_dynamic_volume="      - ./traefik-dynamic.yaml:/etc/traefik/dynamic.yaml:ro"

    local proxy_depends="
      netbird-server:
        condition: service_started"
    if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
      proxy_depends="
      netbird-server:
        condition: service_started
      crowdsec:
        condition: service_healthy"
    fi

    proxy_service="
  # NetBird Proxy - exposes internal resources to the internet
  proxy:
    image: $NETBIRD_PROXY_IMAGE
    container_name: netbird-proxy
    ports:
    - 51820:51820/udp
    restart: unless-stopped
    networks: [netbird]
    depends_on:${proxy_depends}
    env_file:
      - ./proxy.env
    volumes:
      - netbird_proxy_certs:/certs
    labels:
      # TCP passthrough for any unmatched domain (proxy handles its own TLS)
      - traefik.enable=true
      - traefik.tcp.routers.proxy-passthrough.entrypoints=websecure
      - traefik.tcp.routers.proxy-passthrough.rule=HostSNI(\`*\`)
      - traefik.tcp.routers.proxy-passthrough.tls.passthrough=true
      - traefik.tcp.routers.proxy-passthrough.service=proxy-tls
      - traefik.tcp.routers.proxy-passthrough.priority=1
      - traefik.tcp.services.proxy-tls.loadbalancer.server.port=8443
      - traefik.tcp.services.proxy-tls.loadbalancer.serverstransport=pp-v2@file
    logging:
      driver: \"json-file\"
      options:
        max-size: \"500m\"
        max-file: \"2\"
"
    proxy_volumes="
  netbird_proxy_certs:"

    if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
      crowdsec_service="
  crowdsec:
    image: $CROWDSEC_IMAGE
    container_name: netbird-crowdsec
    restart: unless-stopped
    networks: [netbird]
    environment:
      COLLECTIONS: crowdsecurity/linux
    volumes:
      - ./crowdsec:/etc/crowdsec
      - crowdsec_db:/var/lib/crowdsec/data
    healthcheck:
      test: [\"CMD\", \"cscli\", \"lapi\", \"status\"]
      interval: 10s
      timeout: 5s
      retries: 15
    labels:
      - traefik.enable=false
    logging:
      driver: \"json-file\"
      options:
        max-size: \"500m\"
        max-file: \"2\"
"
      crowdsec_volumes="
  crowdsec_db:"
    fi
  fi

  cat <<EOF
services:
  # Traefik reverse proxy (automatic TLS via Let's Encrypt)
  traefik:
    image: $TRAEFIK_IMAGE
    container_name: netbird-traefik
    restart: unless-stopped
    mem_limit: ${LOCAL_TRAEFIK_MEMORY_LIMIT}
    pids_limit: 256
    networks:
      netbird:
        ipv4_address: $TRAEFIK_IP
    command:
      # Logging
      - "--log.level=INFO"
      - "--accesslog=true"
      # Docker provider
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--providers.docker.network=netbird"
      # Entrypoints
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--entrypoints.websecure.allowACMEByPass=true"
      # Disable timeouts for long-lived gRPC streams
      - "--entrypoints.websecure.transport.respondingTimeouts.readTimeout=0"
      - "--entrypoints.websecure.transport.respondingTimeouts.writeTimeout=0"
      - "--entrypoints.websecure.transport.respondingTimeouts.idleTimeout=0"
      # HTTP to HTTPS redirect
      - "--entrypoints.web.http.redirections.entrypoint.to=websecure"
      - "--entrypoints.web.http.redirections.entrypoint.scheme=https"
      # Let's Encrypt ACME
      - "--certificatesresolvers.letsencrypt.acme.email=$TRAEFIK_ACME_EMAIL"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
      - "--certificatesresolvers.letsencrypt.acme.tlschallenge=true"
      # gRPC transport settings
      - "--serverstransport.forwardingtimeouts.responseheadertimeout=0s"
      - "--serverstransport.forwardingtimeouts.idleconntimeout=0s"
$traefik_file_provider
    ports:
      - '443:443'
      - '80:80'
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - netbird_traefik_letsencrypt:/letsencrypt
$traefik_dynamic_volume
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # UI dashboard
  dashboard:
    image: $DASHBOARD_IMAGE
    container_name: netbird-dashboard
    restart: unless-stopped
    networks: [netbird]
    env_file:
      - ./dashboard.env
    labels:
      - traefik.enable=true
      - traefik.http.routers.netbird-dashboard.rule=Host(\`$NETBIRD_DOMAIN\`)
      - traefik.http.routers.netbird-dashboard.entrypoints=websecure
      - traefik.http.routers.netbird-dashboard.tls=true
      - traefik.http.routers.netbird-dashboard.tls.certresolver=letsencrypt
      - traefik.http.routers.netbird-dashboard.service=dashboard
      - traefik.http.routers.netbird-dashboard.priority=1
      - traefik.http.services.dashboard.loadbalancer.server.port=80
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Combined server (Management + Signal + Relay + STUN)
  netbird-server:
    image: $NETBIRD_SERVER_IMAGE
    container_name: netbird-server
    restart: unless-stopped
    networks: [netbird]
    ports:
      - '$NETBIRD_STUN_PORT:$NETBIRD_STUN_PORT/udp'
    volumes:
      - netbird_data:/var/lib/netbird
      - ./config.yaml:/etc/netbird/config.yaml
    command: ["--config", "/etc/netbird/config.yaml"]
    labels:
      - traefik.enable=true
      # gRPC router (needs h2c backend for HTTP/2 cleartext)
      - traefik.http.routers.netbird-grpc.rule=Host(\`$NETBIRD_DOMAIN\`) && (PathPrefix(\`/signalexchange.SignalExchange/\`) || PathPrefix(\`/management.ManagementService/\`) || PathPrefix(\`/management.ProxyService/\`))
      - traefik.http.routers.netbird-grpc.entrypoints=websecure
      - traefik.http.routers.netbird-grpc.tls=true
      - traefik.http.routers.netbird-grpc.tls.certresolver=letsencrypt
      - traefik.http.routers.netbird-grpc.service=netbird-server-h2c
      - traefik.http.routers.netbird-grpc.priority=100
      # Backend router (relay, WebSocket, API, OAuth2)
      - traefik.http.routers.netbird-backend.rule=Host(\`$NETBIRD_DOMAIN\`) && (PathPrefix(\`/relay\`) || PathPrefix(\`/ws-proxy/\`) || PathPrefix(\`/api\`) || PathPrefix(\`/oauth2\`))
      - traefik.http.routers.netbird-backend.entrypoints=websecure
      - traefik.http.routers.netbird-backend.tls=true
      - traefik.http.routers.netbird-backend.tls.certresolver=letsencrypt
      - traefik.http.routers.netbird-backend.service=netbird-server
      - traefik.http.routers.netbird-backend.priority=100
      # Services
      - traefik.http.services.netbird-server.loadbalancer.server.port=80
      - traefik.http.services.netbird-server-h2c.loadbalancer.server.port=80
      - traefik.http.services.netbird-server-h2c.loadbalancer.server.scheme=h2c
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"
${proxy_service}${crowdsec_service}
volumes:
  netbird_data:
  netbird_traefik_letsencrypt:${proxy_volumes}${crowdsec_volumes}

networks:
  netbird:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.0.0/24
          gateway: 172.30.0.1
EOF
  return 0
}

render_combined_yaml() {
  cat <<EOF
# Combined NetBird Server Configuration (Simplified)
# Generated by getting-started.sh

server:
  listenAddress: ":80"
  exposedAddress: "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN:$NETBIRD_PORT"
  stunPorts:
    - $NETBIRD_STUN_PORT
  metricsPort: 9090
  healthcheckAddress: ":9000"
  logLevel: "info"
  logFile: "console"

  authSecret: "$NETBIRD_RELAY_AUTH_SECRET"
  dataDir: "/var/lib/netbird"

  auth:
    issuer: "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/oauth2"
    signKeyRefreshEnabled: true
    dashboardRedirectURIs:
      - "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/nb-auth"
      - "$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/nb-silent-auth"
    cliRedirectURIs:
      - "http://localhost:53000/"

  reverseProxy:
    trustedHTTPProxies:
      - "$TRAEFIK_IP/32"

  store:
    engine: "sqlite"
    encryptionKey: "$DATASTORE_ENCRYPTION_KEY"
EOF
  return 0
}

render_dashboard_env() {
  cat <<EOF
# Endpoints
NETBIRD_MGMT_API_ENDPOINT=$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN
NETBIRD_MGMT_GRPC_API_ENDPOINT=$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN
# OIDC - using embedded IdP
AUTH_AUDIENCE=netbird-dashboard
AUTH_CLIENT_ID=netbird-dashboard
AUTH_CLIENT_SECRET=
AUTH_AUTHORITY=$NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN/oauth2
USE_AUTH0=false
AUTH_SUPPORTED_SCOPES=openid profile email groups
AUTH_REDIRECT_URI=/nb-auth
AUTH_SILENT_REDIRECT_URI=/nb-silent-auth
# SSL
NGINX_SSL_PORT=443
# Letsencrypt
LETSENCRYPT_DOMAIN=none
NETBIRD_LOCAL_INTEGRATIONS_ENABLED=true
NETBIRD_LOCAL_LDAP_SYNC_ENABLED=true
NETBIRD_LOCAL_EDR_ENABLED=true
EOF

  if [[ "${NETBIRD_AGENT_NETWORK}" == "true" ]]; then
    cat <<EOF
# Agent-network preset: dashboard hides the standard NetBird surfaces
# and exposes only the AI Observability + agent-network configuration
# pages. Paired with NB_PROXY_PRIVATE=true on the proxy side.
NETBIRD_AGENT_NETWORK_ONLY=true
EOF
  fi
  return 0
}

render_traefik_dynamic() {
  cat <<'EOF'
tcp:
  serversTransports:
    pp-v2:
      proxyProtocol:
        version: 2
EOF
  return 0
}

render_proxy_env() {
  cat <<EOF
# NetBird Proxy Configuration
NB_PROXY_DEBUG_LOGS=false
# Use internal Docker network to connect to management (avoids hairpin NAT issues)
NB_PROXY_MANAGEMENT_ADDRESS=http://netbird-server:80
# Allow insecure gRPC connection to management (required for internal Docker network)
NB_PROXY_ALLOW_INSECURE=true
# Public URL where this proxy is reachable (used for cluster registration)
NB_PROXY_DOMAIN=$NETBIRD_DOMAIN
NB_PROXY_ADDRESS=:8443
NB_PROXY_TOKEN=$PROXY_TOKEN
NB_PROXY_CERTIFICATE_DIRECTORY=/certs
NB_PROXY_ACME_CERTIFICATES=true
NB_PROXY_ACME_CHALLENGE_TYPE=tls-alpn-01
NB_PROXY_FORWARDED_PROTO=https
# Enable PROXY protocol to preserve client IPs through L4 proxies (Traefik TCP passthrough)
NB_PROXY_PROXY_PROTOCOL=true
# Trust Traefik's IP for PROXY protocol headers
NB_PROXY_TRUSTED_PROXIES=$TRAEFIK_IP
EOF

  if [[ "${NETBIRD_AGENT_NETWORK}" == "true" ]]; then
    cat <<EOF
# Agent-network preset: turn the proxy into the private reverse-proxy
# ingress for agent-network synth services. Disables the public-facing
# surface so the proxy serves only synth-generated routes (the
# llm_router-driven LLM endpoints) and the per-account inbound
# listeners on the embedded netstack.
NB_PROXY_PRIVATE=true
EOF
  fi

  if [[ "$ENABLE_CROWDSEC" == "true" && -n "$CROWDSEC_BOUNCER_KEY" ]]; then
    cat <<EOF
NB_PROXY_CROWDSEC_API_URL=http://crowdsec:8080
NB_PROXY_CROWDSEC_API_KEY=$CROWDSEC_BOUNCER_KEY
EOF
  fi

  return 0
}

render_docker_compose_traefik() {
  local network_name="${TRAEFIK_EXTERNAL_NETWORK:-netbird}"
  local network_config=""
  if [[ -n "$TRAEFIK_EXTERNAL_NETWORK" ]]; then
    network_config="    external: true"
  fi

  # Build TLS labels - certresolver is optional
  local tls_labels=""
  if [[ -n "$TRAEFIK_CERTRESOLVER" ]]; then
    tls_labels="tls.certresolver=${TRAEFIK_CERTRESOLVER}"
  fi

  cat <<EOF
services:
  # UI dashboard
  dashboard:
    image: $DASHBOARD_IMAGE
    container_name: netbird-dashboard
    restart: unless-stopped
    networks: [$network_name]
    env_file:
      - ./dashboard.env
    labels:
      - traefik.enable=true
      - traefik.http.routers.netbird-dashboard.rule=Host(\`$NETBIRD_DOMAIN\`)
      - traefik.http.routers.netbird-dashboard.entrypoints=$TRAEFIK_ENTRYPOINT
      - traefik.http.routers.netbird-dashboard.tls=true
$(if [[ -n "$tls_labels" ]]; then echo "      - traefik.http.routers.netbird-dashboard.${tls_labels}"; fi)
      - traefik.http.routers.netbird-dashboard.priority=1
      - traefik.http.services.netbird-dashboard.loadbalancer.server.port=80
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Combined server (Management + Signal + Relay + STUN)
  netbird-server:
    image: $NETBIRD_SERVER_IMAGE
    container_name: netbird-server
    restart: unless-stopped
    networks: [$network_name]
    ports:
      - '$NETBIRD_STUN_PORT:$NETBIRD_STUN_PORT/udp'
    volumes:
      - netbird_data:/var/lib/netbird
      - ./config.yaml:/etc/netbird/config.yaml
    command: ["--config", "/etc/netbird/config.yaml"]
    labels:
      - traefik.enable=true
      # gRPC router (needs h2c backend for HTTP/2 cleartext)
      - traefik.http.routers.netbird-grpc.rule=Host(\`$NETBIRD_DOMAIN\`) && (PathPrefix(\`/signalexchange.SignalExchange/\`) || PathPrefix(\`/management.ManagementService/\`))
      - traefik.http.routers.netbird-grpc.entrypoints=$TRAEFIK_ENTRYPOINT
      - traefik.http.routers.netbird-grpc.tls=true
$(if [[ -n "$tls_labels" ]]; then echo "      - traefik.http.routers.netbird-grpc.${tls_labels}"; fi)
      - traefik.http.routers.netbird-grpc.service=netbird-server-h2c
      # Backend router (relay, WebSocket, API, OAuth2)
      - traefik.http.routers.netbird-backend.rule=Host(\`$NETBIRD_DOMAIN\`) && (PathPrefix(\`/relay\`) || PathPrefix(\`/ws-proxy/\`) || PathPrefix(\`/api\`) || PathPrefix(\`/oauth2\`))
      - traefik.http.routers.netbird-backend.entrypoints=$TRAEFIK_ENTRYPOINT
      - traefik.http.routers.netbird-backend.tls=true
$(if [[ -n "$tls_labels" ]]; then echo "      - traefik.http.routers.netbird-backend.${tls_labels}"; fi)
      - traefik.http.routers.netbird-backend.service=netbird-server
      # Services
      - traefik.http.services.netbird-server.loadbalancer.server.port=80
      - traefik.http.services.netbird-server-h2c.loadbalancer.server.port=80
      - traefik.http.services.netbird-server-h2c.loadbalancer.server.scheme=h2c
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

volumes:
  netbird_data:

networks:
  $network_name:
$network_config
EOF
  return 0
}

render_docker_compose_exposed_ports() {
  local bind_addr
  bind_addr=$(get_bind_address)
  local networks="[netbird]"
  local networks_config="networks:
  netbird:"

  # If an external network is specified, add it and include in service networks
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    networks="[netbird, $EXTERNAL_PROXY_NETWORK]"
    networks_config="networks:
  netbird:
  $EXTERNAL_PROXY_NETWORK:
    external: true"
  fi

  cat <<EOF
services:
  # UI dashboard
  dashboard:
    image: $DASHBOARD_IMAGE
    container_name: netbird-dashboard
    restart: unless-stopped
    networks: ${networks}
    ports:
      - '${bind_addr}:${DASHBOARD_HOST_PORT}:80'
    env_file:
      - ./dashboard.env
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

  # Combined server (Management + Signal + Relay + STUN)
  netbird-server:
    image: $NETBIRD_SERVER_IMAGE
    container_name: netbird-server
    restart: unless-stopped
    networks: ${networks}
    ports:
      - '${bind_addr}:${MANAGEMENT_HOST_PORT}:80'
      - '$NETBIRD_STUN_PORT:$NETBIRD_STUN_PORT/udp'
    volumes:
      - netbird_data:/var/lib/netbird
      - ./config.yaml:/etc/netbird/config.yaml
    command: ["--config", "/etc/netbird/config.yaml"]
    logging:
      driver: "json-file"
      options:
        max-size: "500m"
        max-file: "2"

volumes:
  netbird_data:

${networks_config}
EOF
  return 0
}

render_nginx_conf() {
  local upstream_host
  upstream_host=$(get_upstream_host)
  local dashboard_addr="${upstream_host}:${DASHBOARD_HOST_PORT}"
  local server_addr="${upstream_host}:${MANAGEMENT_HOST_PORT}"
  local install_note="# 1. Update SSL certificate paths below
# 2. Copy to your nginx config directory:
#    Debian/Ubuntu: /etc/nginx/sites-available/netbird (then symlink to sites-enabled)
#    RHEL/CentOS:   /etc/nginx/conf.d/netbird.conf
# 3. Test and reload: nginx -t && systemctl reload nginx"

  # If running in Docker network, use container names
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    dashboard_addr="netbird-dashboard:80"
    server_addr="netbird-server:80"
    install_note="# This config uses container names since Nginx is on the same Docker network.
# Add this to your nginx.conf or include it from a separate file."
  fi

  cat <<EOF
# NetBird Nginx Configuration
# Generated by getting-started.sh
#
${install_note}

upstream netbird_dashboard {
    server ${dashboard_addr};
    keepalive 10;
}
upstream netbird_server {
    server ${server_addr};
}

server {
    listen 80;
    server_name $NETBIRD_DOMAIN;

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name $NETBIRD_DOMAIN;

    # SSL/TLS Configuration
    # Update these paths based on your certificate source:
    #
    # Let's Encrypt (certbot):
    #   ssl_certificate /etc/letsencrypt/live/$NETBIRD_DOMAIN/fullchain.pem;
    #   ssl_certificate_key /etc/letsencrypt/live/$NETBIRD_DOMAIN/privkey.pem;
    #
    # Let's Encrypt (acme.sh):
    #   ssl_certificate /root/.acme.sh/$NETBIRD_DOMAIN/fullchain.cer;
    #   ssl_certificate_key /root/.acme.sh/$NETBIRD_DOMAIN/$NETBIRD_DOMAIN.key;
    #
    # Custom certificates:
    #   ssl_certificate /etc/ssl/certs/$NETBIRD_DOMAIN.crt;
    #   ssl_certificate_key /etc/ssl/private/$NETBIRD_DOMAIN.key;
    #
    ssl_certificate /path/to/your/fullchain.pem;
    ssl_certificate_key /path/to/your/privkey.pem;

    # Recommended SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;

    # Required for long-lived gRPC connections
    client_header_timeout 1d;
    client_body_timeout 1d;

    # Common proxy headers
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Scheme \$scheme;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Host \$host;
    grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;

    # WebSocket connections (relay, signal, management)
    location ~ ^/(relay|ws-proxy/) {
        proxy_pass http://netbird_server;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 1d;
    }

    # Native gRPC (signal + management)
    location ~ ^/(signalexchange\.SignalExchange|management\.ManagementService)/ {
        grpc_pass grpc://netbird_server;
        grpc_read_timeout 1d;
        grpc_send_timeout 1d;
        grpc_socket_keepalive on;
    }

    # HTTP routes (API + OAuth2)
    location ~ ^/(api|oauth2)/ {
        proxy_pass http://netbird_server;
        proxy_set_header Host \$host;
    }

    # Dashboard (catch-all)
    location / {
        proxy_pass http://netbird_dashboard;
    }
}
EOF
  return 0
}

render_external_caddyfile() {
  local upstream_host
  upstream_host=$(get_upstream_host)
  local dashboard_addr="${upstream_host}:${DASHBOARD_HOST_PORT}"
  local server_addr="${upstream_host}:${MANAGEMENT_HOST_PORT}"
  local install_note="# Add this block to your existing Caddyfile and reload Caddy"

  # If running in Docker network, use container names
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    dashboard_addr="netbird-dashboard:80"
    server_addr="netbird-server:80"
    install_note="# This config uses container names since Caddy is on the same Docker network.
# Add this block to your Caddyfile and reload Caddy."
  fi

  cat <<EOF
# NetBird Caddyfile Snippet
# Generated by getting-started.sh
#
${install_note}

$NETBIRD_DOMAIN {
    # Native gRPC (needs HTTP/2 cleartext to backend)
    @grpc header Content-Type application/grpc*
    reverse_proxy @grpc h2c://${server_addr}

    # Combined server paths (relay, signal, management, OAuth2)
    @backend path /relay* /ws-proxy/* /api/* /oauth2/*
    reverse_proxy @backend ${server_addr}

    # Dashboard (everything else)
    reverse_proxy /* ${dashboard_addr}
}
EOF
  return 0
}

render_npm_advanced_config() {
  local upstream_host
  upstream_host=$(get_upstream_host)
  local server_addr="${upstream_host}:${MANAGEMENT_HOST_PORT}"

  # If external network is specified, use container names instead of host addresses
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    server_addr="netbird-server:80"
  fi

  cat <<EOF
# Advanced Configuration for Nginx Proxy Manager
# Paste this into the "Advanced" tab of your Proxy Host configuration
#
# IMPORTANT: Enable "HTTP/2 Support" in the SSL tab for gRPC to work!

# Required for long-lived connections (gRPC and WebSocket)
client_header_timeout 1d;
client_body_timeout 1d;

# WebSocket connections (relay, signal, management)
location ~ ^/(relay|ws-proxy/) {
    proxy_pass http://${server_addr};
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_read_timeout 1d;
}

# Native gRPC (signal + management)
location ~ ^/(signalexchange\.SignalExchange|management\.ManagementService)/ {
    grpc_pass grpc://${server_addr};
    grpc_read_timeout 1d;
    grpc_send_timeout 1d;
    grpc_socket_keepalive on;
}

# HTTP routes (API + OAuth2)
location ~ ^/(api|oauth2)/ {
    proxy_pass http://${server_addr};
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
}
EOF
  return 0
}

############################################
# Post-Setup Instructions per Proxy Type
############################################

print_builtin_traefik_instructions() {
  echo ""
  echo "$MSG_SEPARATOR"
  echo "  NETBIRD SETUP COMPLETE"
  echo "$MSG_SEPARATOR"
  echo ""
  echo "You can access the NetBird dashboard at:"
  echo "  $NETBIRD_HTTP_PROTOCOL://$NETBIRD_DOMAIN"
  echo ""
  echo "Follow the onboarding steps to set up your NetBird instance."
  echo ""
  echo "Traefik is handling TLS certificates automatically via Let's Encrypt."
  echo "If you see certificate warnings, wait a moment for certificate issuance to complete."
  echo ""
  echo "Open ports:"
  echo "  - 443/tcp   (HTTPS - all NetBird services)"
  echo "  - 80/tcp    (HTTP - redirects to HTTPS)"
  echo "  - $NETBIRD_STUN_PORT/udp   (STUN - required for NAT traversal)"
  if [[ "$ENABLE_PROXY" == "true" ]]; then
    echo "  - 51820/udp (WIREGUARD - (optional) for P2P proxy connections)"
  fi
  echo ""
  if [[ "${NETBIRD_AGENT_NETWORK}" == "true" ]]; then
    echo "For enterprise environments requiring high availability and advanced integrations,"
    echo "consider a commercial on-prem license:"
    echo ""
    echo "  Commercial license: https://netbird.ai/pricing"
    echo "  Documentation: https://docs.netbird.io/agent-network"
  else
    echo "This setup is ideal for homelabs and smaller organization deployments."
    echo "For enterprise environments requiring high availability and advanced integrations,"
    echo "consider a commercial on-prem license or scaling your open source deployment:"
    echo ""
    echo "  Commercial license: https://netbird.io/pricing#on-prem"
    echo "  Scaling guide:      https://docs.netbird.io/scaling-your-self-hosted-deployment"
  fi
  echo ""
  if [[ "$ENABLE_PROXY" == "true" ]]; then
    echo "NetBird Proxy:"
    echo "  The proxy service is enabled and running."
    echo "  Any domain NOT matching $NETBIRD_DOMAIN will be passed through to the proxy."
    echo "  The proxy handles its own TLS certificates via ACME TLS-ALPN-01 challenge."
    echo "  Point your proxy domain to this server's domain address like in the examples below:"
    echo ""
    echo "  *.$NETBIRD_DOMAIN    CNAME    $NETBIRD_DOMAIN"
    echo ""
    if [[ "$ENABLE_CROWDSEC" == "true" ]]; then
      echo "CrowdSec IP Reputation:"
      echo "  CrowdSec LAPI is running and connected to the community blocklist."
      echo "  The proxy will automatically check client IPs against known threats."
      echo "  Enable CrowdSec per-service in the dashboard under Access Control."
      echo ""
      echo "  To enroll in CrowdSec Console (optional, for dashboard and premium blocklists):"
      echo "    docker exec netbird-crowdsec cscli console enroll <your-enrollment-key>"
      echo "  Get your enrollment key at: https://app.crowdsec.net"
      echo ""
    fi
  fi
  if [[ "${NETBIRD_AGENT_NETWORK}" == "true" ]]; then
    echo "Note: The public domain is only for setting up secure connections."
    echo "Your APIs and agent services remain private and are never exposed publicly."
    echo ""
  fi
  return 0
}

print_traefik_instructions() {
  echo ""
  echo "$MSG_SEPARATOR"
  echo "  TRAEFIK SETUP"
  echo "$MSG_SEPARATOR"
  echo ""
  echo "NetBird containers are configured with Traefik labels."
  echo ""
  echo "Configuration:"
  echo "  Entrypoint: $TRAEFIK_ENTRYPOINT"
  if [[ -n "$TRAEFIK_CERTRESOLVER" ]]; then
    echo "  Certificate resolver: $TRAEFIK_CERTRESOLVER"
  fi
  if [[ -n "$TRAEFIK_EXTERNAL_NETWORK" ]]; then
    echo "  Network: $TRAEFIK_EXTERNAL_NETWORK (external)"
  else
    echo "  Network: netbird"
  fi
  echo ""
  echo "$MSG_NEXT_STEPS"
  echo "  - Ensure Traefik is running and configured"
  if [[ -n "$TRAEFIK_EXTERNAL_NETWORK" ]]; then
    echo "  - Traefik must be on the '$TRAEFIK_EXTERNAL_NETWORK' network"
  fi
  echo "  - Entrypoint '$TRAEFIK_ENTRYPOINT' must be defined"
  if [[ -n "$TRAEFIK_CERTRESOLVER" ]]; then
    echo "  - Certificate resolver '$TRAEFIK_CERTRESOLVER' must be configured"
  fi
  echo "  - Disable read timeout on the entrypoint for gRPC streams:"
  echo "    --entrypoints.$TRAEFIK_ENTRYPOINT.transport.respondingTimeouts.readTimeout=0"
  echo "  - HTTP to HTTPS redirect (recommended)"
  return 0
}

print_nginx_instructions() {
  local bind_addr
  bind_addr=$(get_bind_address)
  echo ""
  echo "$MSG_SEPARATOR"
  echo "  NGINX SETUP"
  echo "$MSG_SEPARATOR"
  echo ""
  echo "Generated: nginx-netbird.conf"
  echo ""
  echo "IMPORTANT: Nginx requires manual TLS certificate setup."
  echo "You'll need to obtain SSL/TLS certificates and configure the paths in the"
  echo "generated config file. The config includes examples for common certificate sources."
  echo ""
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    echo "NetBird containers have joined the '$EXTERNAL_PROXY_NETWORK' Docker network."
    echo "The config uses container names for upstream servers."
    echo ""
    echo "$MSG_NEXT_STEPS"
    echo "  1. Ensure your Nginx container has access to SSL certificates"
    echo "     (mount certificate directory as volume if needed)"
    echo "  2. Edit nginx-netbird.conf and update SSL certificate paths"
    echo "     The config includes examples for certbot, acme.sh, and custom certs"
    echo "  3. Include the config in your Nginx container's configuration"
    echo "  4. Reload Nginx"
  else
    echo "$MSG_NEXT_STEPS"
    echo "  1. Obtain SSL/TLS certificates (Let's Encrypt recommended)"
    echo "  2. Edit nginx-netbird.conf and update certificate paths"
    echo "  3. Install to /etc/nginx/sites-available/ (Debian) or /etc/nginx/conf.d/ (RHEL)"
    echo "  4. Test and reload: nginx -t && systemctl reload nginx"
    echo ""
    echo "For detailed TLS setup instructions, see:"
    echo "https://docs.netbird.io/selfhosted/reverse-proxy#tls-certificate-setup-for-nginx"
    echo ""
    echo "Container ports (bound to ${bind_addr}):"
    echo "  Dashboard:     ${DASHBOARD_HOST_PORT}"
    echo "  NetBird Server: ${MANAGEMENT_HOST_PORT} (all services)"
  fi
  return 0
}

print_npm_instructions() {
  local bind_addr upstream_host
  bind_addr=$(get_bind_address)
  upstream_host=$(get_upstream_host)
  echo ""
  echo "$MSG_SEPARATOR"
  echo "  NGINX PROXY MANAGER SETUP"
  echo "$MSG_SEPARATOR"
  echo ""
  echo "Generated: npm-advanced-config.txt"
  echo ""
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    echo "NetBird containers have joined the '$EXTERNAL_PROXY_NETWORK' Docker network."
    echo ""
    echo "In NPM, create a Proxy Host:"
    echo "  Domain: $NETBIRD_DOMAIN"
    echo "  Forward Hostname: netbird-dashboard"
    echo "  Forward Port: 80"
    echo "  Block Common Exploits: enabled"
    echo ""
    echo "  SSL tab:"
    echo "    - Request or select existing certificate"
    echo "    - Enable 'HTTP/2 Support' (REQUIRED for gRPC)"
    echo ""
    echo "  Advanced tab:"
    echo "    - Paste contents of npm-advanced-config.txt"
  else
    echo "Container ports (bound to ${bind_addr}):"
    echo "  Dashboard:     ${DASHBOARD_HOST_PORT}"
    echo "  NetBird Server: ${MANAGEMENT_HOST_PORT} (all services)"
    echo ""
    echo "In NPM, create a Proxy Host:"
    echo "  Domain: $NETBIRD_DOMAIN"
    echo "  Forward Hostname/IP: ${upstream_host}"
    echo "  Forward Port: ${DASHBOARD_HOST_PORT}"
    echo "  Block Common Exploits: enabled"
    echo ""
    echo "  SSL tab:"
    echo "    - Request or select existing certificate"
    echo "    - Enable 'HTTP/2 Support' (REQUIRED for gRPC)"
    echo ""
    echo "  Advanced tab:"
    echo "    - Paste contents of npm-advanced-config.txt"
  fi
  return 0
}

print_external_caddy_instructions() {
  local bind_addr
  bind_addr=$(get_bind_address)
  echo ""
  echo "$MSG_SEPARATOR"
  echo "  EXTERNAL CADDY SETUP"
  echo "$MSG_SEPARATOR"
  echo ""
  echo "Generated: caddyfile-netbird.txt"
  echo ""
  if [[ -n "$EXTERNAL_PROXY_NETWORK" ]]; then
    echo "NetBird containers have joined the '$EXTERNAL_PROXY_NETWORK' Docker network."
    echo "The config uses container names for upstream servers."
    echo ""
    echo "$MSG_NEXT_STEPS"
    echo "  1. Add the contents of caddyfile-netbird.txt to your Caddyfile"
    echo "  2. Reload Caddy"
  else
    echo "$MSG_NEXT_STEPS"
    echo "  1. Add the contents of caddyfile-netbird.txt to your Caddyfile"
    echo "  2. Reload Caddy: caddy reload --config /path/to/Caddyfile"
    echo ""
    echo "Container ports (bound to ${bind_addr}):"
    echo "  Dashboard:     ${DASHBOARD_HOST_PORT}"
    echo "  NetBird Server: ${MANAGEMENT_HOST_PORT} (all services)"
  fi
  return 0
}

print_manual_instructions() {
  local bind_addr upstream_host
  bind_addr=$(get_bind_address)
  upstream_host=$(get_upstream_host)
  echo ""
  echo "$MSG_SEPARATOR"
  echo "  MANUAL REVERSE PROXY SETUP"
  echo "$MSG_SEPARATOR"
  echo ""
  echo "Container ports (bound to ${bind_addr}):"
  echo "  Dashboard:     ${DASHBOARD_HOST_PORT}"
  echo "  NetBird Server: ${MANAGEMENT_HOST_PORT} (all services: management, signal, relay)"
  echo ""
  echo "Configure your reverse proxy with these routes (all go to the same backend):"
  echo ""
  echo "  WebSocket (relay, signal, management WS proxy):"
  echo "    /relay*, /ws-proxy/*           -> ${upstream_host}:${MANAGEMENT_HOST_PORT}"
  echo "    (HTTP with WebSocket upgrade, extended timeout)"
  echo ""
  echo "  Native gRPC (signal + management):"
  echo "    /signalexchange.SignalExchange/* -> ${upstream_host}:${MANAGEMENT_HOST_PORT}"
  echo "    /management.ManagementService/* -> ${upstream_host}:${MANAGEMENT_HOST_PORT}"
  echo "    (gRPC/h2c - plaintext HTTP/2)"
  echo ""
  echo "  HTTP (API + embedded IdP):"
  echo "    /api/*, /oauth2/*              -> ${upstream_host}:${MANAGEMENT_HOST_PORT}"
  echo ""
  echo "  Dashboard (catch-all):"
  echo "    /*                             -> ${upstream_host}:${DASHBOARD_HOST_PORT}"
  echo ""
  echo "IMPORTANT: gRPC routes require HTTP/2 (h2c) upstream support."
  echo "WebSocket and gRPC connections need extended timeouts (recommend 1 day)."
  return 0
}

print_post_setup_instructions() {
  case "$REVERSE_PROXY_TYPE" in
    0)
      print_builtin_traefik_instructions
      ;;
    1)
      print_traefik_instructions
      ;;
    2)
      print_nginx_instructions
      ;;
    3)
      print_npm_instructions
      ;;
    4)
      print_external_caddy_instructions
      ;;
    5)
      print_manual_instructions
      ;;
    *)
      echo "Unknown reverse proxy type: $REVERSE_PROXY_TYPE" > /dev/stderr
      ;;
  esac
  return 0
}

############################################
# Local source-build deployment
############################################

local_detect_compose() {
  if docker compose version >/dev/null 2>&1; then
    LOCAL_COMPOSE_BIN=(docker compose)
    return 0
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    LOCAL_COMPOSE_BIN=(docker-compose)
    return 0
  fi

  echo "docker compose is required for the local deployment." > /dev/stderr
  exit 1
}

local_acquire_deployment_lock() {
  mkdir -p "$LOCAL_RUNTIME_DIR"
  LOCAL_DEPLOYMENT_LOCK="${LOCAL_RUNTIME_DIR}/deployment.lock"
  if ! mkdir "$LOCAL_DEPLOYMENT_LOCK" 2>/dev/null; then
    echo "Another NetBird deployment operation is already running: ${LOCAL_DEPLOYMENT_LOCK}" > /dev/stderr
    exit 1
  fi
  trap 'rmdir "$LOCAL_DEPLOYMENT_LOCK" 2>/dev/null || true' EXIT INT TERM
}

local_build_images() {
	local -a build_command=(docker build)
  if [[ "${NETBIRD_BUILD_PULL:-false}" == "true" ]]; then
	  build_command+=(--pull)
  fi
  if [[ "${NETBIRD_BUILD_NO_CACHE:-false}" == "true" ]]; then
	  build_command+=(--no-cache)
  fi

  echo "Building local NetBird server ${LOCAL_IMAGE_VERSION}..."
	"${build_command[@]}" \
    --build-arg "NETBIRD_VERSION=${LOCAL_IMAGE_VERSION}" \
    --label "org.opencontainers.image.revision=${LOCAL_SOURCE_COMMIT_ID}" \
    --label "netbird.local.main-commit=${LOCAL_MAIN_COMMIT_ID}" \
    --label "netbird.local.source-dirty=${LOCAL_SOURCE_DIRTY}" \
    -f "${LOCAL_REPO_ROOT}/combined/Dockerfile.multistage" \
    -t "${LOCAL_IMAGE_PREFIX}/netbird-server:${LOCAL_IMAGE_VERSION}" \
    "$LOCAL_REPO_ROOT"

  echo "Building local dashboard ${LOCAL_DASHBOARD_IMAGE_VERSION}..."
	"${build_command[@]}" \
    --build-arg "NEXT_PUBLIC_DASHBOARD_VERSION=${LOCAL_DASHBOARD_IMAGE_VERSION}" \
    --label "org.opencontainers.image.revision=${LOCAL_DASHBOARD_SOURCE_COMMIT_ID}" \
    --label "netbird.local.main-commit=${LOCAL_DASHBOARD_MAIN_COMMIT_ID}" \
    --label "netbird.local.source-dirty=${LOCAL_DASHBOARD_SOURCE_DIRTY}" \
    -f "${LOCAL_DASHBOARD_ROOT}/Dockerfile.multistage" \
    -t "${LOCAL_IMAGE_PREFIX}/dashboard:${LOCAL_DASHBOARD_IMAGE_VERSION}" \
    "$LOCAL_DASHBOARD_ROOT"
}

local_resolve_main_commit() {
  local main_ref="${NETBIRD_MAIN_REF:-origin/main}"
  local dashboard_main_ref="${NETBIRD_DASHBOARD_MAIN_REF:-origin/main}"

  if ! LOCAL_MAIN_COMMIT_ID=$(git -C "$LOCAL_REPO_ROOT" rev-parse --verify "${main_ref}^{commit}" 2>/dev/null); then
    echo "Unable to resolve main commit from '$main_ref'. Fetch origin/main first." > /dev/stderr
    exit 1
  fi

  LOCAL_SOURCE_COMMIT_ID=$(git -C "$LOCAL_REPO_ROOT" rev-parse --verify HEAD)
	LOCAL_SOURCE_DIRTY=false
  if [[ "$LOCAL_SOURCE_COMMIT_ID" != "$LOCAL_MAIN_COMMIT_ID" ]]; then
    echo "WARNING: HEAD is not ${main_ref}; the requested image version remains the main commit ID." > /dev/stderr
    echo "  HEAD: ${LOCAL_SOURCE_COMMIT_ID}" > /dev/stderr
    echo "  main: ${LOCAL_MAIN_COMMIT_ID}" > /dev/stderr
  fi
  if [[ -n "$(git -C "$LOCAL_REPO_ROOT" status --porcelain --untracked-files=all -- . ':(exclude)dashboard' ':(exclude)deploy/runtime' ':(exclude)deploy/docker-compose.yml' ':(exclude)deploy/config.local.yaml' ':(exclude)deploy/dashboard.local.env' ':(exclude)deploy/traefik.local.yaml' ':(exclude)deploy/ldap-bootstrap.local.ldif')" ]]; then
	LOCAL_SOURCE_DIRTY=true
    if [[ "${NETBIRD_ALLOW_DIRTY_BUILD:-false}" != "true" ]]; then
      echo "Server source contains uncommitted changes; refusing a non-reproducible production image." > /dev/stderr
      echo "Commit the changes, or set NETBIRD_ALLOW_DIRTY_BUILD=true for an explicitly non-production build." > /dev/stderr
      exit 1
    fi
    echo "WARNING: NETBIRD_ALLOW_DIRTY_BUILD=true; server image is not reproducible." > /dev/stderr
  fi

  if ! LOCAL_DASHBOARD_MAIN_COMMIT_ID=$(git -C "$LOCAL_DASHBOARD_ROOT" rev-parse --verify "${dashboard_main_ref}^{commit}" 2>/dev/null); then
    echo "Unable to resolve dashboard main commit from '$dashboard_main_ref'. Fetch dashboard origin/main first." > /dev/stderr
    exit 1
  fi

  LOCAL_DASHBOARD_SOURCE_COMMIT_ID=$(git -C "$LOCAL_DASHBOARD_ROOT" rev-parse --verify HEAD)
	LOCAL_DASHBOARD_SOURCE_DIRTY=false
  if [[ "$LOCAL_DASHBOARD_SOURCE_COMMIT_ID" != "$LOCAL_DASHBOARD_MAIN_COMMIT_ID" ]]; then
    echo "WARNING: dashboard HEAD is not ${dashboard_main_ref}; the dashboard image version remains the dashboard main commit ID." > /dev/stderr
    echo "  dashboard HEAD: ${LOCAL_DASHBOARD_SOURCE_COMMIT_ID}" > /dev/stderr
    echo "  dashboard main: ${LOCAL_DASHBOARD_MAIN_COMMIT_ID}" > /dev/stderr
  fi
  if [[ -n "$(git -C "$LOCAL_DASHBOARD_ROOT" status --porcelain)" ]]; then
	LOCAL_DASHBOARD_SOURCE_DIRTY=true
    if [[ "${NETBIRD_ALLOW_DIRTY_BUILD:-false}" != "true" ]]; then
      echo "Dashboard source contains uncommitted changes; refusing a non-reproducible production image." > /dev/stderr
      echo "Commit the changes, or set NETBIRD_ALLOW_DIRTY_BUILD=true for an explicitly non-production build." > /dev/stderr
      exit 1
    fi
    echo "WARNING: NETBIRD_ALLOW_DIRTY_BUILD=true; dashboard image is not reproducible." > /dev/stderr
  fi

  LOCAL_MAIN_BRANCH="${NETBIRD_IMAGE_BRANCH:-${main_ref#*/}}"
  LOCAL_MAIN_BRANCH=$(printf '%s' "$LOCAL_MAIN_BRANCH" | sed 's/[^A-Za-z0-9_.-]/-/g')
  LOCAL_MAIN_COMMIT_SHORT="${LOCAL_MAIN_COMMIT_ID:0:8}"
  if [[ -z "$LOCAL_MAIN_BRANCH" ]]; then
    echo "Unable to derive an image branch name from '$main_ref'." > /dev/stderr
    exit 1
  fi
  LOCAL_IMAGE_VERSION="${LOCAL_MAIN_BRANCH}-${LOCAL_MAIN_COMMIT_SHORT}"

  LOCAL_DASHBOARD_MAIN_BRANCH="${NETBIRD_DASHBOARD_IMAGE_BRANCH:-${dashboard_main_ref#*/}}"
  LOCAL_DASHBOARD_MAIN_BRANCH=$(printf '%s' "$LOCAL_DASHBOARD_MAIN_BRANCH" | sed 's/[^A-Za-z0-9_.-]/-/g')
  LOCAL_DASHBOARD_MAIN_COMMIT_SHORT="${LOCAL_DASHBOARD_MAIN_COMMIT_ID:0:8}"
  if [[ -z "$LOCAL_DASHBOARD_MAIN_BRANCH" ]]; then
    echo "Unable to derive a dashboard image branch name from '$dashboard_main_ref'." > /dev/stderr
    exit 1
  fi
  LOCAL_DASHBOARD_IMAGE_VERSION="${LOCAL_DASHBOARD_MAIN_BRANCH}-${LOCAL_DASHBOARD_MAIN_COMMIT_SHORT}"
}

local_quick_tunnel_url_from_logs() {
  docker logs "$LOCAL_TUNNEL_CONTAINER" 2>&1 \
    | sed -nE 's#.*(https://[a-z0-9-]+\.trycloudflare\.com).*#\1#p' \
    | head -n 1
}

local_start_quick_tunnel() {
  local container_running tunnel_url started_at

  if [[ "$LOCAL_ACTION" != "deploy" ]]; then
    echo "NETBIRD_QUICK_TUNNEL=true is only supported with NETBIRD_LOCAL_ACTION=deploy." > /dev/stderr
    exit 1
  fi

  container_running=$(docker inspect --format '{{.State.Running}}' "$LOCAL_TUNNEL_CONTAINER" 2>/dev/null || true)
  if [[ -n "$container_running" && "$container_running" != "true" ]]; then
    docker rm -f "$LOCAL_TUNNEL_CONTAINER" >/dev/null
    container_running=""
  fi

  if [[ "$container_running" != "true" ]]; then
    if ! docker network inspect "$LOCAL_TUNNEL_BOOTSTRAP_NETWORK" >/dev/null 2>&1; then
      docker network create \
        --label netbird.local.quick-tunnel=true \
        "$LOCAL_TUNNEL_BOOTSTRAP_NETWORK" >/dev/null
    fi

    echo "Starting a temporary Cloudflare Quick Tunnel in a container..."
    docker run -d \
      --name "$LOCAL_TUNNEL_CONTAINER" \
      --restart unless-stopped \
      --network "$LOCAL_TUNNEL_BOOTSTRAP_NETWORK" \
      --security-opt no-new-privileges:true \
      "$LOCAL_CLOUDFLARED_IMAGE" \
      tunnel --no-autoupdate --protocol http2 \
      --url "https://${LOCAL_PROJECT_NAME}-traefik:443" --no-tls-verify >/dev/null
  else
    echo "Reusing running temporary Cloudflare Quick Tunnel container."
  fi

  started_at=$SECONDS
  tunnel_url=$(local_quick_tunnel_url_from_logs)
  while [[ -z "$tunnel_url" && $((SECONDS - started_at)) -lt 60 ]]; do
    sleep 2
    tunnel_url=$(local_quick_tunnel_url_from_logs)
  done
  if [[ -z "$tunnel_url" ]]; then
    echo "Cloudflare Quick Tunnel did not return a temporary hostname." > /dev/stderr
    docker logs --tail=100 "$LOCAL_TUNNEL_CONTAINER" > /dev/stderr
    exit 1
  fi

  LOCAL_DOMAIN="${tunnel_url#https://}"
  if [[ ! "$LOCAL_DOMAIN" =~ ^[a-z0-9-]+\.trycloudflare\.com$ ]]; then
    echo "Unexpected Quick Tunnel hostname: $LOCAL_DOMAIN" > /dev/stderr
    exit 1
  fi

  mkdir -p "$LOCAL_RUNTIME_DIR"
  printf '%s\n' "$LOCAL_DOMAIN" > "$LOCAL_TUNNEL_DOMAIN_FILE"
  chmod 600 "$LOCAL_TUNNEL_DOMAIN_FILE"
  echo "Temporary public URL: https://${LOCAL_DOMAIN}"
}

local_attach_quick_tunnel() {
  local attached_networks

  if ! docker network inspect "$LOCAL_COMPOSE_NETWORK" >/dev/null 2>&1; then
    echo "Compose network is unavailable for Quick Tunnel: $LOCAL_COMPOSE_NETWORK" > /dev/stderr
    exit 1
  fi
  attached_networks=$(docker inspect --format '{{range $name, $_ := .NetworkSettings.Networks}}{{println $name}}{{end}}' "$LOCAL_TUNNEL_CONTAINER")
  if ! grep -Fxq "$LOCAL_COMPOSE_NETWORK" <<< "$attached_networks"; then
    docker network connect "$LOCAL_COMPOSE_NETWORK" "$LOCAL_TUNNEL_CONTAINER"
  fi
}

local_stop_quick_tunnel() {
  docker rm -f "$LOCAL_TUNNEL_CONTAINER" >/dev/null 2>&1 || true
  docker network rm "$LOCAL_TUNNEL_BOOTSTRAP_NETWORK" >/dev/null 2>&1 || true
  rm -f "$LOCAL_TUNNEL_DOMAIN_FILE"
}

local_stop_deployment() {
  local_stop_quick_tunnel
  if [[ -f "$LOCAL_COMPOSE_FILE" && -f "$LOCAL_SECRETS_FILE" ]]; then
    LOCAL_COMPOSE=("${LOCAL_COMPOSE_BIN[@]}" --project-name "$LOCAL_PROJECT_NAME" --env-file "$LOCAL_SECRETS_FILE" -f "$LOCAL_COMPOSE_FILE")
    "${LOCAL_COMPOSE[@]}" down --remove-orphans
  fi
  echo "NetBird containers and temporary tunnel stopped."
  echo "Compose, generated configuration, TLS material, secrets, and persistent data volumes were kept."
}

local_env_value() {
  local key="$1"
  awk -F= -v key="$key" '$1 == key {sub(/^[^=]*=/, ""); print; exit}' "$LOCAL_SECRETS_FILE"
}

local_prepare_secrets() {
  local previous_umask

  mkdir -p "$LOCAL_RUNTIME_DIR"

  if [[ -L "$LOCAL_SECRETS_FILE" ]]; then
    echo "Refusing to use symlinked secrets file: $LOCAL_SECRETS_FILE" > /dev/stderr
    exit 1
  fi

  previous_umask=$(umask)
  umask 077
  docker run --rm \
    --entrypoint sh \
    -e HOST_UID="$(id -u)" \
    -e HOST_GID="$(id -g)" \
    -v "$LOCAL_RUNTIME_DIR:/runtime" \
    osixia/openldap:1.5.0 -ec '
      secrets_file=/runtime/secrets.env
      umask 077
      if [ ! -f "$secrets_file" ]; then
        {
          printf "POSTGRES_USER=netbird\n"
          printf "POSTGRES_PASSWORD=%s\n" "$(openssl rand -hex 24)"
          printf "POSTGRES_DB=netbird\n"
          printf "LDAP_ADMIN_PASSWORD=%s\n" "$(openssl rand -hex 24)"
          printf "LDAP_BOOTSTRAP_USER_PASSWORD=Nb-%s-Aa1!\n" "$(openssl rand -hex 12)"
          printf "LDAP_BOOTSTRAP_ADMIN_PASSWORD=Nb-%s-Aa1!\n" "$(openssl rand -hex 12)"
          printf "NETBIRD_ADMIN_PASSWORD=Nb-%s-Aa1!\n" "$(openssl rand -hex 12)"
          printf "NETBIRD_RELAY_AUTH_SECRET=%s\n" "$(openssl rand -base64 32 | tr -d "=\n")"
          printf "NETBIRD_DATASTORE_ENCRYPTION_KEY=%s\n" "$(openssl rand -base64 32 | tr -d "\n")"
        } > "$secrets_file"
      fi
      if ! grep -q "^LDAP_BOOTSTRAP_USER_PASSWORD=" "$secrets_file"; then
        printf "LDAP_BOOTSTRAP_USER_PASSWORD=Nb-%s-Aa1!\n" "$(openssl rand -hex 12)" >> "$secrets_file"
      fi
      if ! grep -q "^LDAP_BOOTSTRAP_ADMIN_PASSWORD=" "$secrets_file"; then
        printf "LDAP_BOOTSTRAP_ADMIN_PASSWORD=Nb-%s-Aa1!\n" "$(openssl rand -hex 12)" >> "$secrets_file"
      fi
      chmod 600 "$secrets_file"
      chown "${HOST_UID}:${HOST_GID}" "$secrets_file"
    '

  chmod 600 "$LOCAL_SECRETS_FILE"
  POSTGRES_USER=$(local_env_value POSTGRES_USER)
  POSTGRES_PASSWORD=$(local_env_value POSTGRES_PASSWORD)
  POSTGRES_DB=$(local_env_value POSTGRES_DB)
  LDAP_ADMIN_PASSWORD=$(local_env_value LDAP_ADMIN_PASSWORD)
  LDAP_BOOTSTRAP_USER_PASSWORD=$(local_env_value LDAP_BOOTSTRAP_USER_PASSWORD)
  LDAP_BOOTSTRAP_ADMIN_PASSWORD=$(local_env_value LDAP_BOOTSTRAP_ADMIN_PASSWORD)
  NETBIRD_ADMIN_PASSWORD=$(local_env_value NETBIRD_ADMIN_PASSWORD)
  NETBIRD_RELAY_AUTH_SECRET=$(local_env_value NETBIRD_RELAY_AUTH_SECRET)
  DATASTORE_ENCRYPTION_KEY=$(local_env_value NETBIRD_DATASTORE_ENCRYPTION_KEY)

  local required_value
  for required_value in POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB LDAP_ADMIN_PASSWORD \
    LDAP_BOOTSTRAP_USER_PASSWORD LDAP_BOOTSTRAP_ADMIN_PASSWORD NETBIRD_ADMIN_PASSWORD \
    NETBIRD_RELAY_AUTH_SECRET DATASTORE_ENCRYPTION_KEY; do
    if [[ -z "${!required_value}" ]]; then
      echo "Missing ${required_value} in ${LOCAL_SECRETS_FILE}" > /dev/stderr
      exit 1
    fi
  done
  umask "$previous_umask"
}

local_render_ldap_bootstrap() {
  local previous_umask

  if [[ -L "$LOCAL_LDAP_BOOTSTRAP_FILE" ]]; then
    echo "Refusing to use symlinked LDAP bootstrap file: ${LOCAL_LDAP_BOOTSTRAP_FILE}" > /dev/stderr
    exit 1
  fi
  previous_umask=$(umask)
  umask 077
  if [[ "$LOCAL_BOOTSTRAP_TEST_USERS" != "true" ]]; then
    cat > "$LOCAL_LDAP_BOOTSTRAP_FILE" <<'EOF'
# Generated by getting-started-local.sh. No test user accounts are created.
dn: ou=users,dc=example,dc=org
objectClass: organizationalUnit
ou: users

dn: ou=groups,dc=example,dc=org
objectClass: organizationalUnit
ou: groups

dn: cn=netbird-users,ou=groups,dc=example,dc=org
objectClass: groupOfNames
cn: netbird-users
member: cn=admin,dc=example,dc=org

dn: cn=netbird,ou=groups,dc=example,dc=org
objectClass: groupOfNames
cn: netbird
member: cn=admin,dc=example,dc=org
EOF
    chmod 600 "$LOCAL_LDAP_BOOTSTRAP_FILE"
    umask "$previous_umask"
    return 0
  fi
  cat > "$LOCAL_LDAP_BOOTSTRAP_FILE" <<EOF
# Generated by getting-started-local.sh. Contains bootstrap credentials.
dn: ou=users,dc=example,dc=org
objectClass: organizationalUnit
ou: users

dn: ou=groups,dc=example,dc=org
objectClass: organizationalUnit
ou: groups

dn: uid=ldapuser,ou=users,dc=example,dc=org
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: ldapuser
sn: User
givenName: LDAP
cn: LDAP User
displayName: LDAP User
uidNumber: 10000
gidNumber: 10000
userPassword: ${LDAP_BOOTSTRAP_USER_PASSWORD}
homeDirectory: /home/ldapuser
mail: ldapuser@example.org
loginShell: /bin/bash

dn: uid=ldapadmin,ou=users,dc=example,dc=org
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: ldapadmin
sn: Admin
givenName: LDAP
cn: LDAP Admin
displayName: LDAP Admin
uidNumber: 10001
gidNumber: 10000
userPassword: ${LDAP_BOOTSTRAP_ADMIN_PASSWORD}
homeDirectory: /home/ldapadmin
mail: ldapadmin@example.org
loginShell: /bin/bash

dn: cn=netbird-users,ou=groups,dc=example,dc=org
objectClass: groupOfNames
cn: netbird-users
member: uid=ldapuser,ou=users,dc=example,dc=org
member: uid=ldapadmin,ou=users,dc=example,dc=org

dn: cn=netbird,ou=groups,dc=example,dc=org
objectClass: groupOfNames
cn: netbird
member: uid=ldapuser,ou=users,dc=example,dc=org
member: uid=ldapadmin,ou=users,dc=example,dc=org
EOF
  chmod 600 "$LOCAL_LDAP_BOOTSTRAP_FILE"
  umask "$previous_umask"
}

local_has_interactive_tty() {
  [[ -r /dev/tty && -w /dev/tty ]] && [[ -t 0 || -t 1 || -t 2 ]]
}

local_prompt_domain() {
  echo "" > /dev/stderr
  echo "Enter the domain that will be used to access NetBird." > /dev/stderr
  echo "Example: netbird.example.com" > /dev/stderr
  echo -n "NetBird domain: " > /dev/stderr
  if ! read -r LOCAL_DOMAIN < /dev/tty; then
    echo "Unable to read the domain from the terminal." > /dev/stderr
    exit 1
  fi
  if [[ -z "$LOCAL_DOMAIN" ]]; then
    echo "The NetBird domain cannot be empty." > /dev/stderr
    exit 1
  fi
}

local_prompt_tls_mode() {
  local tls_choice

  echo "" > /dev/stderr
  echo "Choose how Traefik should provide HTTPS:" > /dev/stderr
  echo "  1) Let's Encrypt (recommended for a public server)" > /dev/stderr
  echo "  2) Self-signed certificate (LAN or temporary testing)" > /dev/stderr
  echo -n "TLS mode [1]: " > /dev/stderr
  if ! read -r tls_choice < /dev/tty; then
    echo "Unable to read the TLS mode from the terminal." > /dev/stderr
    exit 1
  fi

  case "$tls_choice" in
    ""|1|letsencrypt)
      LOCAL_TLS_MODE="letsencrypt"
      ;;
    2|selfsigned)
      LOCAL_TLS_MODE="selfsigned"
      ;;
    *)
      echo "Invalid TLS mode: ${tls_choice}" > /dev/stderr
      exit 1
      ;;
  esac
}

local_prompt_acme_email() {
  echo "" > /dev/stderr
  echo "Enter an email for Let's Encrypt expiry and account notifications." > /dev/stderr
  echo -n "Let's Encrypt email: " > /dev/stderr
  if ! read -r LOCAL_ACME_EMAIL < /dev/tty; then
    echo "Unable to read the Let's Encrypt email from the terminal." > /dev/stderr
    exit 1
  fi
}

local_resolve_domain_and_tls_mode() {
  LOCAL_ACME_EMAIL="${NETBIRD_LETSENCRYPT_EMAIL:-}"

  if [[ "$LOCAL_QUICK_TUNNEL" == "true" ]]; then
    case "$LOCAL_TLS_MODE" in
      auto|selfsigned)
        LOCAL_TLS_MODE="selfsigned"
        ;;
      letsencrypt)
        echo "NETBIRD_TLS_MODE=letsencrypt cannot be combined with NETBIRD_QUICK_TUNNEL=true." > /dev/stderr
        exit 1
        ;;
      *)
        echo "NETBIRD_TLS_MODE must be 'auto', 'letsencrypt', or 'selfsigned'." > /dev/stderr
        exit 1
        ;;
    esac
    return 0
  fi

  if [[ -z "$LOCAL_DOMAIN" ]]; then
    if local_has_interactive_tty; then
      local_prompt_domain
    else
      echo "NETBIRD_DOMAIN is required in non-interactive mode." > /dev/stderr
      echo "Example: NETBIRD_DOMAIN=netbird.example.com NETBIRD_TLS_MODE=letsencrypt NETBIRD_LETSENCRYPT_EMAIL=admin@example.com bash ${LOCAL_SCRIPT_DIR}/getting-started-local.sh" > /dev/stderr
      exit 1
    fi
  fi

  case "$LOCAL_TLS_MODE" in
    auto)
      if [[ "$LOCAL_DEPLOYMENT_MODE" == "production" ]]; then
		LOCAL_TLS_MODE="letsencrypt"
      elif [[ -n "$LOCAL_ACME_EMAIL" ]]; then
        LOCAL_TLS_MODE="letsencrypt"
      elif local_has_interactive_tty; then
        local_prompt_tls_mode
      else
        LOCAL_TLS_MODE="selfsigned"
        echo "WARNING: NETBIRD_TLS_MODE=auto is using a self-signed certificate because this run is non-interactive and NETBIRD_LETSENCRYPT_EMAIL is empty." > /dev/stderr
      fi
      ;;
    letsencrypt|selfsigned)
      ;;
    *)
      echo "NETBIRD_TLS_MODE must be 'auto', 'letsencrypt', or 'selfsigned'." > /dev/stderr
      exit 1
      ;;
  esac

  if [[ "$LOCAL_TLS_MODE" == "letsencrypt" ]]; then
    if [[ -z "$LOCAL_ACME_EMAIL" ]]; then
      if local_has_interactive_tty; then
        local_prompt_acme_email
      else
        echo "NETBIRD_LETSENCRYPT_EMAIL is required when NETBIRD_TLS_MODE=letsencrypt is used non-interactively." > /dev/stderr
        exit 1
      fi
    fi
    if [[ ! "$LOCAL_ACME_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z0-9-]{2,63}$ ]]; then
      echo "Invalid Let's Encrypt email: ${LOCAL_ACME_EMAIL}" > /dev/stderr
      exit 1
    fi

    echo "" > /dev/stderr
    echo "Let's Encrypt prerequisites:" > /dev/stderr
    echo "  - ${LOCAL_DOMAIN} must resolve publicly to this server." > /dev/stderr
    echo "  - Inbound TCP ports 80 and 443 must reach ${LOCAL_BIND_IP}." > /dev/stderr
    echo "  - Inbound UDP port ${LOCAL_STUN_PORT} must reach ${LOCAL_BIND_IP}." > /dev/stderr
    echo "  - If Cloudflare DNS is used, keep the NetBird record DNS-only so STUN UDP is not proxied." > /dev/stderr
    echo "" > /dev/stderr
  fi

  if [[ "$LOCAL_DEPLOYMENT_MODE" == "production" && "$LOCAL_TLS_MODE" != "letsencrypt" ]]; then
    echo "Production mode requires Traefik with a publicly trusted Let's Encrypt certificate." > /dev/stderr
    exit 1
  fi
}

local_validate_domain_and_network() {
  local octet octet_value
  local -a local_ip_octets

  if [[ -z "$LOCAL_DOMAIN" ]]; then
    echo "NETBIRD_DOMAIN is required for local deployment." > /dev/stderr
    echo "Use a real subdomain that you control when requesting a publicly trusted certificate." > /dev/stderr
    exit 1
  fi

  if [[ ! "$LOCAL_DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || [[ "$LOCAL_DOMAIN" != *.* ]]; then
    echo "Invalid local test domain: $LOCAL_DOMAIN" > /dev/stderr
    exit 1
  fi
  if [[ "$LOCAL_DOMAIN" == "test" || "$LOCAL_DOMAIN" == *.test ]]; then
    echo "Reserved .test domains cannot be used for a publicly trusted certificate." > /dev/stderr
    exit 1
  fi

  if [[ ! "$LOCAL_BIND_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "Invalid local bind IPv4 address: $LOCAL_BIND_IP" > /dev/stderr
    exit 1
  fi
  IFS='.' read -r -a local_ip_octets <<< "$LOCAL_BIND_IP"
  for octet in "${local_ip_octets[@]}"; do
    octet_value=$((10#$octet))
    if (( octet_value < 0 || octet_value > 255 )); then
      echo "Invalid local bind IPv4 address: $LOCAL_BIND_IP" > /dev/stderr
      exit 1
    fi
  done
  if [[ "$LOCAL_BIND_IP" == 127.* || "$LOCAL_BIND_IP" == "0.0.0.0" ]]; then
    echo "NETBIRD_BIND_IP must be a LAN address, not $LOCAL_BIND_IP." > /dev/stderr
    exit 1
  fi

  if [[ ! "$LOCAL_STUN_PORT" =~ ^[0-9]+$ ]] || (( LOCAL_STUN_PORT < 1 || LOCAL_STUN_PORT > 65535 )); then
    echo "Invalid NETBIRD_STUN_PORT: $LOCAL_STUN_PORT" > /dev/stderr
    exit 1
  fi

  LOCAL_BASE_URL="https://${LOCAL_DOMAIN}"
  if [[ -z "$LOCAL_CLIENT_ENDPOINT" ]]; then
    LOCAL_CLIENT_ENDPOINT="$LOCAL_BASE_URL"
  fi
  if [[ ! "$LOCAL_CLIENT_ENDPOINT" =~ ^https?://[^[:space:]]+$ ]]; then
    echo "NETBIRD_CLIENT_ENDPOINT must be an absolute http(s) URL." > /dev/stderr
    exit 1
  fi
  LOCAL_CLIENT_PROXY_PORT=""
  if [[ "$LOCAL_CLIENT_ENDPOINT" =~ ^http://127\.0\.0\.1:([0-9]+)$ ]]; then
    LOCAL_CLIENT_PROXY_PORT="${BASH_REMATCH[1]}"
    if (( LOCAL_CLIENT_PROXY_PORT < 1 || LOCAL_CLIENT_PROXY_PORT > 65535 )); then
      echo "Invalid loopback port in NETBIRD_CLIENT_ENDPOINT: ${LOCAL_CLIENT_PROXY_PORT}" > /dev/stderr
      exit 1
    fi
  fi
}

local_ensure_hosts_entry() {
  local hosts_file="${NETBIRD_HOSTS_FILE:-/etc/hosts}"
  local existing_ip managed_entry hosts_tmp

  if [[ "$LOCAL_QUICK_TUNNEL" == "true" && "$LOCAL_QUICK_TUNNEL_LAN_ACCESS" != "true" ]]; then
    echo "Quick Tunnel uses public DNS; skipping the local hosts file."
    return 0
  fi
  if [[ "$LOCAL_TLS_MODE" == "letsencrypt" ]]; then
    echo "Let's Encrypt uses public DNS; skipping the local hosts file."
    return 0
  fi

  existing_ip=$(awk -v host="$LOCAL_DOMAIN" '
    $1 !~ /^#/ {
      for (i = 2; i <= NF; i++) {
        if ($i == host) {
          print $1
          exit
        }
      }
    }
  ' "$hosts_file")
  managed_entry=$(awk -v host="$LOCAL_DOMAIN" '
    /# netbird-local$/ {
      for (i = 2; i <= NF; i++) {
        if ($i == host) {
          print "true"
          exit
        }
      }
    }
  ' "$hosts_file")

  if [[ "$existing_ip" == "$LOCAL_BIND_IP" ]]; then
    echo "Hosts entry already exists: ${existing_ip} ${LOCAL_DOMAIN}"
    return 0
  fi
  if [[ -n "$existing_ip" && "$managed_entry" != "true" ]]; then
    echo "${LOCAL_DOMAIN} already maps to ${existing_ip} in ${hosts_file}; refusing to override it." > /dev/stderr
    exit 1
  fi
  if [[ "${NETBIRD_SKIP_HOSTS:-false}" == "true" ]]; then
    echo "Skipping hosts update. Add this entry before browser testing:"
    echo "  ${LOCAL_BIND_IP} ${LOCAL_DOMAIN}"
    return 0
  fi

  hosts_tmp=$(mktemp "${TMPDIR:-/tmp}/netbird-hosts.XXXXXX")
  awk -v host="$LOCAL_DOMAIN" -v ip="$LOCAL_BIND_IP" '
    BEGIN { updated = 0 }
    /# netbird-local$/ {
      for (i = 2; i <= NF; i++) {
        if ($i == host) {
          print ip " " host " # netbird-local"
          updated = 1
          next
        }
      }
    }
    { print }
    END {
      if (!updated) {
        print ip " " host " # netbird-local"
      }
    }
  ' "$hosts_file" > "$hosts_tmp"

  echo "Updating local hosts entry (sudo may prompt for your computer password):"
  echo "  ${LOCAL_BIND_IP} ${LOCAL_DOMAIN}"
  if [[ -w "$hosts_file" ]]; then
    tee "$hosts_file" < "$hosts_tmp" >/dev/null
  elif command -v sudo >/dev/null 2>&1; then
    sudo sh -c 'tee "$1" < "$2" >/dev/null' sh "$hosts_file" "$hosts_tmp"
  else
    rm -f "$hosts_tmp"
    echo "Cannot update ${hosts_file}; rerun with NETBIRD_SKIP_HOSTS=true and add the entry manually." > /dev/stderr
    exit 1
  fi
  rm -f "$hosts_tmp"
}

local_prepare_tls_certificate() {
  local tls_metadata="${LOCAL_TLS_DIR}/metadata"
  local expected_metadata="${LOCAL_DOMAIN} ${LOCAL_BIND_IP}"

  if [[ "$LOCAL_TLS_MODE" == "letsencrypt" ]]; then
    echo "Traefik will request and renew the HTTPS certificate through Let's Encrypt."
    return 0
  fi

  mkdir -p "$LOCAL_TLS_DIR"
  if [[ -L "$LOCAL_TLS_CERT_FILE" || -L "$LOCAL_TLS_KEY_FILE" ]]; then
    echo "Refusing to use symlinked TLS files in ${LOCAL_TLS_DIR}." > /dev/stderr
    exit 1
  fi

  if [[ ! -f "$LOCAL_TLS_CERT_FILE" || ! -f "$LOCAL_TLS_KEY_FILE" || ! -f "$tls_metadata" || "$(<"$tls_metadata")" != "$expected_metadata" ]]; then
    echo "Generating a local HTTPS certificate for ${LOCAL_DOMAIN} (${LOCAL_BIND_IP}) in a container..."
    rm -f "$LOCAL_TLS_CERT_FILE" "$LOCAL_TLS_KEY_FILE" "$tls_metadata"
    docker run --rm \
      -e HOST_UID="$(id -u)" \
      -e HOST_GID="$(id -g)" \
      -e TLS_DOMAIN="$LOCAL_DOMAIN" \
      -e TLS_IP="$LOCAL_BIND_IP" \
      -v "$LOCAL_TLS_DIR:/tls" \
      alpine:3.21 sh -ec '
        apk add --no-cache openssl >/dev/null
        openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 \
          -keyout /tls/netbird.key -out /tls/netbird.crt \
          -subj "/CN=${TLS_DOMAIN}" \
          -addext "subjectAltName=DNS:${TLS_DOMAIN},IP:${TLS_IP}" \
          -addext "keyUsage=digitalSignature,keyEncipherment" \
          -addext "extendedKeyUsage=serverAuth"
        chown "${HOST_UID}:${HOST_GID}" /tls/netbird.key /tls/netbird.crt
      '
    printf '%s\n' "$expected_metadata" > "$tls_metadata"
  fi

  chmod 600 "$LOCAL_TLS_KEY_FILE"
  chmod 644 "$LOCAL_TLS_CERT_FILE" "$tls_metadata"
}

local_prepare_ldap_tls_certificate() {
  local tls_metadata="${LOCAL_LDAP_TLS_DIR}/metadata"
  local expected_metadata="${LOCAL_PROJECT_NAME}"

  mkdir -p "$LOCAL_LDAP_TLS_DIR"
  if [[ -L "$LOCAL_LDAP_CA_CERT_FILE" || -L "$LOCAL_LDAP_CA_KEY_FILE" \
    || -L "$LOCAL_LDAP_CERT_FILE" || -L "$LOCAL_LDAP_KEY_FILE" ]]; then
    echo "Refusing to use symlinked LDAP TLS files in ${LOCAL_LDAP_TLS_DIR}." > /dev/stderr
    exit 1
  fi

  if [[ ! -f "$LOCAL_LDAP_CA_CERT_FILE" || ! -f "$LOCAL_LDAP_CA_KEY_FILE" \
    || ! -f "$LOCAL_LDAP_CERT_FILE" || ! -f "$LOCAL_LDAP_KEY_FILE" \
    || ! -f "$tls_metadata" || "$(<"$tls_metadata")" != "$expected_metadata" ]]; then
    echo "Generating a private CA and OpenLDAP server certificate in a container..."
    rm -f "$LOCAL_LDAP_CA_CERT_FILE" "$LOCAL_LDAP_CA_KEY_FILE" \
      "$LOCAL_LDAP_CERT_FILE" "$LOCAL_LDAP_KEY_FILE" "$tls_metadata"
    docker run --rm \
      -e HOST_UID="$(id -u)" \
      -e HOST_GID="$(id -g)" \
      -e LDAP_CONTAINER_NAME="${LOCAL_PROJECT_NAME}-openldap" \
      -v "$LOCAL_LDAP_TLS_DIR:/tls" \
      alpine:3.21 sh -ec '
        apk add --no-cache openssl >/dev/null
        openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 \
          -keyout /tls/ca.key -out /tls/ca.crt \
          -subj "/CN=NetBird Local OpenLDAP CA" \
          -addext "basicConstraints=critical,CA:TRUE" \
          -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
        openssl req -new -newkey rsa:3072 -sha256 -nodes \
          -keyout /tls/ldap.key -out /tmp/ldap.csr \
          -subj "/CN=openldap" \
          -addext "subjectAltName=DNS:openldap,DNS:${LDAP_CONTAINER_NAME}" \
          -addext "keyUsage=digitalSignature,keyEncipherment" \
          -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1
        printf "%s\n" \
          "subjectAltName=DNS:openldap,DNS:${LDAP_CONTAINER_NAME}" \
          "basicConstraints=critical,CA:FALSE" \
          "keyUsage=critical,digitalSignature,keyEncipherment" \
          "extendedKeyUsage=serverAuth" > /tmp/ldap-ext.cnf
        openssl x509 -req -in /tmp/ldap.csr \
          -CA /tls/ca.crt -CAkey /tls/ca.key -CAcreateserial \
          -out /tls/ldap.crt -days 825 -sha256 -extfile /tmp/ldap-ext.cnf >/dev/null 2>&1
        rm -f /tls/ca.srl /tmp/ldap.csr /tmp/ldap-ext.cnf
        chown "${HOST_UID}:${HOST_GID}" /tls/ca.key /tls/ca.crt /tls/ldap.key /tls/ldap.crt
      '
    printf '%s\n' "$expected_metadata" > "$tls_metadata"
  fi

  chmod 600 "$LOCAL_LDAP_CA_KEY_FILE" "$LOCAL_LDAP_KEY_FILE"
  chmod 644 "$LOCAL_LDAP_CA_CERT_FILE" "$LOCAL_LDAP_CERT_FILE" "$tls_metadata"
}

local_render_server_config() {
  local postgres_dsn="host=postgres port=5432 user=${POSTGRES_USER} password=${POSTGRES_PASSWORD} dbname=${POSTGRES_DB} sslmode=disable TimeZone=UTC"
  local ldap_root_ca
  local previous_umask

  if [[ ! -s "$LOCAL_LDAP_CA_CERT_FILE" ]]; then
    echo "OpenLDAP CA certificate is missing: ${LOCAL_LDAP_CA_CERT_FILE}" > /dev/stderr
    exit 1
  fi
  ldap_root_ca=$(sed 's/^/            /' "$LOCAL_LDAP_CA_CERT_FILE")
  if [[ -L "$LOCAL_CONFIG_FILE" ]]; then
    echo "Refusing to use symlinked server configuration: ${LOCAL_CONFIG_FILE}" > /dev/stderr
    exit 1
  fi
  previous_umask=$(umask)
  umask 077

  cat > "$LOCAL_CONFIG_FILE" <<EOF
# Local source-build configuration. Generated by getting-started-local.sh.
server:
  listenAddress: ":80"
  exposedAddress: "${LOCAL_CLIENT_ENDPOINT}"
  stunPorts:
    - ${LOCAL_STUN_PORT}
  metricsPort: 9090
  healthcheckAddress: ":9000"
  logLevel: "info"
  logFile: "console"

  authSecret: "${NETBIRD_RELAY_AUTH_SECRET}"
  dataDir: "/var/lib/netbird"
  disableGeoliteUpdate: true

  auth:
    issuer: "${LOCAL_BASE_URL}/oauth2"
    signKeyRefreshEnabled: true
    dashboardRedirectURIs:
      - "${LOCAL_BASE_URL}/nb-auth"
      - "${LOCAL_BASE_URL}/nb-silent-auth"
    cliRedirectURIs:
      - "http://localhost:53000/"
    owner:
      email: "admin@${LOCAL_DOMAIN}"
      password: "${NETBIRD_ADMIN_PASSWORD}"
    connectors:
      - type: ldap
        name: "OpenLDAP"
        id: "openldap"
        config:
          host: "openldap:636"
          insecureNoSSL: false
          insecureSkipVerify: false
          rootCA: |
${ldap_root_ca}
          bindDN: "cn=admin,dc=example,dc=org"
          bindPW: "${LDAP_ADMIN_PASSWORD}"
          userSearch:
            baseDN: "ou=users,dc=example,dc=org"
            username: "mail"
            idAttr: "uid"
            emailAttr: "mail"
            nameAttr: "cn"
          groupSearch:
            baseDN: "ou=groups,dc=example,dc=org"
            nameAttr: "cn"
            userMatchers:
              - userAttr: "DN"
                groupAttr: "member"
          requiredGroups:
            - "netbird"

  reverseProxy:
    trustedHTTPProxies:
      - "${LOCAL_TRAEFIK_IP}/32"
    trustedPeers:
      - "${LOCAL_TRAEFIK_IP}/32"

  store:
    engine: "postgres"
    dsn: "${postgres_dsn}"
    encryptionKey: "${DATASTORE_ENCRYPTION_KEY}"

  activityStore:
    engine: "postgres"
    dsn: "${postgres_dsn}"

  authStore:
    engine: "postgres"
    dsn: "${postgres_dsn}"
EOF
  chmod 600 "$LOCAL_CONFIG_FILE"
  umask "$previous_umask"
}

local_render_dashboard_env() {
  cat > "$LOCAL_DASHBOARD_ENV_FILE" <<EOF
NETBIRD_MGMT_API_ENDPOINT=${LOCAL_BASE_URL}
NETBIRD_MGMT_GRPC_API_ENDPOINT=${LOCAL_BASE_URL}
AUTH_AUDIENCE=netbird-dashboard
AUTH_CLIENT_ID=netbird-dashboard
AUTH_CLIENT_SECRET=
AUTH_AUTHORITY=${LOCAL_BASE_URL}/oauth2
USE_AUTH0=false
AUTH_SUPPORTED_SCOPES=openid profile email groups
AUTH_REDIRECT_URI=/nb-auth
AUTH_SILENT_REDIRECT_URI=/nb-silent-auth
NGINX_SSL_PORT=443
LETSENCRYPT_DOMAIN=none
NETBIRD_LOCAL_INTEGRATIONS_ENABLED=true
NETBIRD_LOCAL_LDAP_SYNC_ENABLED=true
NETBIRD_LOCAL_EDR_ENABLED=true
EOF
}

local_render_traefik_config() {
  local router_tls_yaml tls_certificates_yaml

	if [[ "$LOCAL_TLS_MODE" == "letsencrypt" ]]; then
	  router_tls_yaml='      tls:
        certResolver: letsencrypt'
	  tls_certificates_yaml=""
	else
	  router_tls_yaml='      tls: {}'
	  tls_certificates_yaml=$(cat <<'EOF'
tls:
  certificates:
    - certFile: /certs/netbird.crt
      keyFile: /certs/netbird.key
  stores:
    default:
      defaultCertificate:
        certFile: /certs/netbird.crt
        keyFile: /certs/netbird.key
EOF
)
	fi

  cat > "$LOCAL_TRAEFIK_FILE" <<EOF
http:
  routers:
    netbird-grpc:
      rule: "Host(\`${LOCAL_DOMAIN}\`) && (PathPrefix(\`/signalexchange.SignalExchange/\`) || PathPrefix(\`/management.ManagementService/\`) || PathPrefix(\`/management.ProxyService/\`))"
      entryPoints: [websecure]
      service: netbird-server-h2c
      priority: 100
${router_tls_yaml}
    netbird-backend:
      rule: "Host(\`${LOCAL_DOMAIN}\`) && (PathPrefix(\`/relay\`) || PathPrefix(\`/ws-proxy/\`) || PathPrefix(\`/api\`) || PathPrefix(\`/oauth2\`))"
      entryPoints: [websecure]
      service: netbird-server
      priority: 100
${router_tls_yaml}
    netbird-dashboard:
      rule: "Host(\`${LOCAL_DOMAIN}\`)"
      entryPoints: [websecure]
      service: dashboard
      priority: 1
${router_tls_yaml}
  services:
    dashboard:
      loadBalancer:
        servers:
          - url: "http://dashboard:80"
    netbird-server:
      loadBalancer:
        servers:
          - url: "http://netbird-server:80"
    netbird-server-h2c:
      loadBalancer:
        servers:
          - url: "h2c://netbird-server:80"
${tls_certificates_yaml}
EOF
	chmod 600 "$LOCAL_TRAEFIK_FILE"
}

local_render_compose() {
  local client_proxy_yaml=""
  local traefik_ports_yaml=""
  local traefik_tls_commands_yaml=""
  local traefik_tls_mounts_yaml=""
  local traefik_acme_volume_yaml=""
  local smoke_tls_mount_yaml=""

  if [[ "$LOCAL_QUICK_TUNNEL" != "true" || "$LOCAL_QUICK_TUNNEL_LAN_ACCESS" == "true" ]]; then
    if [[ "$LOCAL_TLS_MODE" == "letsencrypt" ]]; then
      traefik_ports_yaml=$(printf '    ports:\n      - "%s:80:80"\n      - "%s:443:443"' "$LOCAL_BIND_IP" "$LOCAL_BIND_IP")
    else
      traefik_ports_yaml=$(printf '    ports:\n      - "%s:443:443"' "$LOCAL_BIND_IP")
    fi
  fi
  if [[ "$LOCAL_TLS_MODE" == "letsencrypt" ]]; then
    traefik_tls_commands_yaml=$(cat <<EOF
      - "--entrypoints.web.address=:80"
      - "--entrypoints.web.http.redirections.entrypoint.to=websecure"
      - "--entrypoints.web.http.redirections.entrypoint.scheme=https"
      - "--certificatesresolvers.letsencrypt.acme.email=${LOCAL_ACME_EMAIL}"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
EOF
)
    traefik_tls_mounts_yaml=$(cat <<EOF
      - ${LOCAL_TRAEFIK_FILE}:/etc/traefik/dynamic.yaml:ro
      - traefik_letsencrypt:/letsencrypt
EOF
)
    traefik_acme_volume_yaml="  traefik_letsencrypt:"
  else
    traefik_tls_commands_yaml=""
    traefik_tls_mounts_yaml=$(cat <<EOF
      - ${LOCAL_TRAEFIK_FILE}:/etc/traefik/dynamic.yaml:ro
      - ${LOCAL_TLS_DIR}:/certs:ro
EOF
)
    smoke_tls_mount_yaml=$(cat <<EOF
    volumes:
      - ${LOCAL_TLS_CERT_FILE}:/certs/netbird.crt:ro
EOF
)
  fi
  if [[ -n "$LOCAL_CLIENT_PROXY_PORT" ]]; then
    client_proxy_yaml=$(cat <<EOF
  client-proxy:
    image: alpine/socat:1.8.0.3
    container_name: ${LOCAL_PROJECT_NAME}-client-proxy
    restart: unless-stopped
    networks: [netbird]
    ports:
      - "127.0.0.1:${LOCAL_CLIENT_PROXY_PORT}:8080"
    command: ["-d", "-d", "TCP-LISTEN:8080,fork,reuseaddr", "TCP:netbird-server:80"]
    depends_on:
      netbird-server:
        condition: service_healthy
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    logging: *default-logging

EOF
)
  fi

  cat > "$LOCAL_COMPOSE_FILE" <<EOF
# Generated by getting-started-local.sh. Do not maintain a second Compose file.
# Manual operations must use: docker compose --env-file runtime/secrets.env -f docker-compose.yml <command>
name: ${LOCAL_PROJECT_NAME}

x-logging: &default-logging
  driver: "json-file"
  options:
    max-size: "50m"
    max-file: "5"

services:
  traefik:
    image: traefik:v3.6
    container_name: ${LOCAL_PROJECT_NAME}-traefik
    restart: unless-stopped
    networks:
      netbird:
        ipv4_address: ${LOCAL_TRAEFIK_IP}
    command:
      - "--entrypoints.websecure.address=:443"
      - "--entrypoints.websecure.http.encodedcharacters.allowencodedslash=false"
      - "--entrypoints.websecure.http.encodedcharacters.allowencodedbackslash=false"
      - "--entrypoints.websecure.http.encodedcharacters.allowencodednullcharacter=false"
      - "--entrypoints.websecure.http.encodedcharacters.allowencodedsemicolon=false"
      - "--entrypoints.websecure.http.encodedcharacters.allowencodedpercent=false"
      - "--entrypoints.websecure.http.encodedcharacters.allowencodedquestionmark=false"
      - "--entrypoints.websecure.http.encodedcharacters.allowencodedhash=false"
${traefik_tls_commands_yaml}
      - "--providers.file.filename=/etc/traefik/dynamic.yaml"
      - "--providers.file.watch=true"
      - "--ping=true"
      - "--api.dashboard=false"
      - "--accesslog=true"
      - "--log.level=INFO"
      - "--global.checknewversion=false"
      - "--global.sendanonymoususage=false"
      - "--serverstransport.forwardingtimeouts.responseheadertimeout=0s"
      - "--serverstransport.forwardingtimeouts.idleconntimeout=0s"
${traefik_ports_yaml}
    volumes:
${traefik_tls_mounts_yaml}
    depends_on:
      dashboard:
        condition: service_healthy
      netbird-server:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "traefik", "healthcheck", "--ping"]
      interval: 5s
      timeout: 3s
      retries: 20
    security_opt:
      - no-new-privileges:true
    logging: *default-logging

  dashboard:
    build:
      context: ${LOCAL_DASHBOARD_ROOT}
      dockerfile: Dockerfile.multistage
      args:
        NEXT_PUBLIC_DASHBOARD_VERSION: "${LOCAL_DASHBOARD_IMAGE_VERSION}"
      labels:
        org.opencontainers.image.revision: "${LOCAL_DASHBOARD_SOURCE_COMMIT_ID}"
        netbird.local.main-commit: "${LOCAL_DASHBOARD_MAIN_COMMIT_ID}"
        netbird.local.source-dirty: "${LOCAL_DASHBOARD_SOURCE_DIRTY}"
    image: ${LOCAL_IMAGE_PREFIX}/dashboard:${LOCAL_DASHBOARD_IMAGE_VERSION}
    pull_policy: never
    container_name: ${LOCAL_PROJECT_NAME}-dashboard
    restart: unless-stopped
    mem_limit: ${LOCAL_DASHBOARD_MEMORY_LIMIT}
    pids_limit: 512
    networks: [netbird]
    env_file:
      - ${LOCAL_DASHBOARD_ENV_FILE}
    depends_on:
      netbird-server:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://127.0.0.1/"]
      interval: 5s
      timeout: 3s
      retries: 20
    labels:
      - "netbird.local.main-commit=${LOCAL_DASHBOARD_MAIN_COMMIT_ID}"
      - "netbird.local.source-commit=${LOCAL_DASHBOARD_SOURCE_COMMIT_ID}"
      - "netbird.local.source-dirty=${LOCAL_DASHBOARD_SOURCE_DIRTY}"
      - "netbird.local.image-version=${LOCAL_DASHBOARD_IMAGE_VERSION}"
    security_opt:
      - no-new-privileges:true
    logging: *default-logging

  netbird-server:
    build:
      context: ${LOCAL_REPO_ROOT}
      dockerfile: combined/Dockerfile.multistage
      args:
        NETBIRD_VERSION: "${LOCAL_IMAGE_VERSION}"
      labels:
        org.opencontainers.image.revision: "${LOCAL_SOURCE_COMMIT_ID}"
        netbird.local.main-commit: "${LOCAL_MAIN_COMMIT_ID}"
        netbird.local.source-dirty: "${LOCAL_SOURCE_DIRTY}"
    image: ${LOCAL_IMAGE_PREFIX}/netbird-server:${LOCAL_IMAGE_VERSION}
    pull_policy: never
    container_name: ${LOCAL_PROJECT_NAME}-server
    restart: unless-stopped
    mem_limit: ${LOCAL_SERVER_MEMORY_LIMIT}
    pids_limit: 1024
    networks: [netbird]
    ports:
      - "${LOCAL_BIND_IP}:${LOCAL_STUN_PORT}:${LOCAL_STUN_PORT}/udp"
    volumes:
      - netbird_data:/var/lib/netbird
      - ${LOCAL_CONFIG_FILE}:/etc/netbird/config.yaml:ro
    environment:
      NB_EXPERIMENT_NETWORK_MAP: "false"
      NB_LOCAL_INTEGRATIONS_ENABLED: "true"
      NB_LOCAL_LDAP_SYNC_ENABLED: "true"
      NB_LOCAL_SCIM_ENABLED: "true"
      NB_LOCAL_EVENT_STREAMING_ENABLED: "true"
      NB_LOCAL_EDR_ENABLED: "true"
      NB_LOCAL_EDR_SYNC_TIMEOUT: "${NB_LOCAL_EDR_SYNC_TIMEOUT:-5m}"
      NB_LOCAL_EDR_FLEETDM_HEALTH_CONCURRENCY: "${NB_LOCAL_EDR_FLEETDM_HEALTH_CONCURRENCY:-25}"
    command: ["--config", "/etc/netbird/config.yaml"]
    depends_on:
      postgres:
        condition: service_healthy
      openldap:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "/bin/bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/9000"]
      interval: 5s
      timeout: 3s
      retries: 30
      start_period: 10s
    labels:
      - "netbird.local.main-commit=${LOCAL_MAIN_COMMIT_ID}"
      - "netbird.local.source-commit=${LOCAL_SOURCE_COMMIT_ID}"
      - "netbird.local.source-dirty=${LOCAL_SOURCE_DIRTY}"
      - "netbird.local.image-version=${LOCAL_IMAGE_VERSION}"
    security_opt:
      - no-new-privileges:true
    stop_grace_period: 30s
    logging: *default-logging

${client_proxy_yaml}
  postgres:
    image: postgres:17-alpine
    container_name: ${LOCAL_PROJECT_NAME}-postgres
    restart: unless-stopped
    mem_limit: ${LOCAL_POSTGRES_MEMORY_LIMIT}
    pids_limit: 512
    networks: [netbird]
    environment:
      POSTGRES_USER: "\${POSTGRES_USER}"
      POSTGRES_PASSWORD: "\${POSTGRES_PASSWORD}"
      POSTGRES_DB: "\${POSTGRES_DB}"
      POSTGRES_INITDB_ARGS: "--auth-host=scram-sha-256"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U \$\${POSTGRES_USER} -d \$\${POSTGRES_DB}"]
      interval: 5s
      timeout: 3s
      retries: 20
    volumes:
      - netbird_postgres:/var/lib/postgresql/data
    security_opt:
      - no-new-privileges:true
    shm_size: 256mb
    stop_grace_period: 60s
    logging: *default-logging

  openldap:
    image: osixia/openldap:1.5.0
    container_name: ${LOCAL_PROJECT_NAME}-openldap
    restart: unless-stopped
    mem_limit: ${LOCAL_LDAP_MEMORY_LIMIT}
    pids_limit: 512
    networks: [netbird]
    environment:
      LDAP_ORGANISATION: "NetBird Local"
      LDAP_DOMAIN: "example.org"
      LDAP_BASE_DN: "dc=example,dc=org"
      LDAP_ADMIN_PASSWORD: "\${LDAP_ADMIN_PASSWORD}"
      LDAP_TLS: "true"
      LDAP_TLS_ENFORCE: "true"
      LDAP_TLS_VERIFY_CLIENT: "never"
      LDAP_SEED_INTERNAL_LDAP_TLS_CRT_FILE: "/cert-seed/ldap.crt"
      LDAP_SEED_INTERNAL_LDAP_TLS_KEY_FILE: "/cert-seed/ldap.key"
      LDAP_SEED_INTERNAL_LDAP_TLS_CA_CRT_FILE: "/cert-seed/ca.crt"
    volumes:
      - ldap_data:/var/lib/ldap
      - ldap_config:/etc/ldap/slapd.d
      - ${LOCAL_LDAP_BOOTSTRAP_FILE}:/container/service/slapd/assets/config/bootstrap/ldif/custom/50-init.ldif:ro
      - ${LOCAL_LDAP_CERT_FILE}:/cert-seed/ldap.crt:ro
      - ${LOCAL_LDAP_KEY_FILE}:/cert-seed/ldap.key:ro
      - ${LOCAL_LDAP_CA_CERT_FILE}:/cert-seed/ca.crt:ro
    command: --copy-service
    healthcheck:
      test: ["CMD-SHELL", "LDAPTLS_REQCERT=never ldapsearch -x -H ldaps://127.0.0.1:636 -b dc=example,dc=org -D cn=admin,dc=example,dc=org -w \$\${LDAP_ADMIN_PASSWORD} >/dev/null"]
      interval: 5s
      timeout: 5s
      retries: 20
      start_period: 10s
    security_opt:
      - no-new-privileges:true
    logging: *default-logging

  smoke-test:
    image: curlimages/curl:8.12.1
    profiles: [smoke]
    networks: [netbird]
${smoke_tls_mount_yaml}
    depends_on:
      traefik:
        condition: service_healthy
    logging: *default-logging

volumes:
  netbird_data:
  netbird_postgres:
  ldap_data:
  ldap_config:
${traefik_acme_volume_yaml}

networks:
  netbird:
    driver: bridge
    ipam:
      config:
        - subnet: ${LOCAL_NETWORK_SUBNET}
EOF
}

local_wait_for_service() {
  local service="$1"
  local timeout_seconds="${2:-180}"
  local started_at=$SECONDS
  local container_id status

  printf 'Waiting for %s' "$service"
  while (( SECONDS - started_at < timeout_seconds )); do
    container_id=$("${LOCAL_COMPOSE[@]}" ps -q "$service")
    if [[ -n "$container_id" ]]; then
      status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)
      if [[ "$status" == "healthy" || "$status" == "running" ]]; then
        echo " ready"
        return 0
      fi
      if [[ "$status" == "unhealthy" || "$status" == "exited" || "$status" == "dead" ]]; then
        echo " failed (${status})" > /dev/stderr
        "${LOCAL_COMPOSE[@]}" logs --tail=100 "$service" > /dev/stderr
        return 1
      fi
    fi
    printf '.'
    sleep 2
  done

  echo " timed out" > /dev/stderr
  "${LOCAL_COMPOSE[@]}" logs --tail=100 "$service" > /dev/stderr
  return 1
}

local_sync_ldap_bootstrap_passwords() {
  local ldap_container="${LOCAL_PROJECT_NAME}-openldap"
	if [[ "$LOCAL_BOOTSTRAP_TEST_USERS" != "true" ]]; then
	  return 0
	fi

  echo "Synchronizing randomized LDAP bootstrap passwords..."
  printf '%s\n%s\n%s\n' \
    "$LDAP_ADMIN_PASSWORD" \
    "$LDAP_BOOTSTRAP_USER_PASSWORD" \
    "$LDAP_BOOTSTRAP_ADMIN_PASSWORD" \
    | docker exec -i "$ldap_container" sh -ec '
        password_dir=$(mktemp -d)
        trap '\''rm -rf "$password_dir"'\'' EXIT
        IFS= read -r bind_password
        IFS= read -r user_password
        IFS= read -r admin_password
        printf %s "$bind_password" > "$password_dir/bind"
        printf %s "$user_password" > "$password_dir/user"
        printf %s "$admin_password" > "$password_dir/admin"
        chmod 600 "$password_dir/bind" "$password_dir/user" "$password_dir/admin"
        LDAPTLS_REQCERT=never ldappasswd -x -H ldaps://127.0.0.1:636 \
          -D cn=admin,dc=example,dc=org -y "$password_dir/bind" \
          -T "$password_dir/user" uid=ldapuser,ou=users,dc=example,dc=org >/dev/null
        LDAPTLS_REQCERT=never ldappasswd -x -H ldaps://127.0.0.1:636 \
          -D cn=admin,dc=example,dc=org -y "$password_dir/bind" \
          -T "$password_dir/admin" uid=ldapadmin,ou=users,dc=example,dc=org >/dev/null
      '
}

local_run_container_smoke_tests() {
  local attempt
  local -a tls_args=()

  if [[ "$LOCAL_TLS_MODE" == "selfsigned" ]]; then
    tls_args=(--cacert /certs/netbird.crt)
  fi

  echo "Running smoke tests from a container..."
  for attempt in $(seq 1 30); do
    if "${LOCAL_COMPOSE[@]}" --profile smoke run --rm --no-deps smoke-test \
      "${tls_args[@]}" --fail --silent --show-error --max-time 15 \
      --resolve "${LOCAL_DOMAIN}:443:${LOCAL_TRAEFIK_IP}" \
      "https://${LOCAL_DOMAIN}/oauth2/.well-known/openid-configuration" -o /dev/null \
      && "${LOCAL_COMPOSE[@]}" --profile smoke run --rm --no-deps smoke-test \
        "${tls_args[@]}" --fail --silent --show-error --max-time 15 \
        --resolve "${LOCAL_DOMAIN}:443:${LOCAL_TRAEFIK_IP}" \
        "https://${LOCAL_DOMAIN}/" -o /dev/null; then
      return 0
    fi
    if (( attempt < 30 )); then
      sleep 2
    fi
  done

  echo "Container HTTPS smoke tests did not become ready." > /dev/stderr
  "${LOCAL_COMPOSE[@]}" logs --tail=100 traefik > /dev/stderr
  return 1
}

local_run_quick_tunnel_smoke_tests() {
  local attempt

  if [[ "$LOCAL_QUICK_TUNNEL" != "true" ]]; then
    return 0
  fi

  echo "Verifying the browser-trusted public HTTPS path from a container..."
  for attempt in $(seq 1 30); do
    if docker run --rm curlimages/curl:8.12.1 \
      --fail --silent --show-error --max-time 15 \
      "${LOCAL_BASE_URL}/oauth2/.well-known/openid-configuration" -o /dev/null; then
      docker run --rm curlimages/curl:8.12.1 \
        --fail --silent --show-error --max-time 15 \
        "${LOCAL_BASE_URL}/" -o /dev/null
      return 0
    fi
    if (( attempt < 30 )); then
      sleep 2
    fi
  done

  echo "Temporary public HTTPS path did not become ready." > /dev/stderr
  docker logs --tail=100 "$LOCAL_TUNNEL_CONTAINER" > /dev/stderr
  return 1
}

run_local_source_deployment() {
  LOCAL_SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  LOCAL_REPO_ROOT=$(cd "${LOCAL_SCRIPT_DIR}/.." && pwd)
  LOCAL_DASHBOARD_ROOT="${LOCAL_REPO_ROOT}/dashboard"
	LOCAL_OUTPUT_DIR="${NETBIRD_OUTPUT_DIR:-${LOCAL_SCRIPT_DIR}}"
	if [[ "$LOCAL_OUTPUT_DIR" != /* ]]; then
	  LOCAL_OUTPUT_DIR="$(cd "$(dirname "$LOCAL_OUTPUT_DIR")" && pwd)/$(basename "$LOCAL_OUTPUT_DIR")"
	fi
	LOCAL_RUNTIME_DIR="${LOCAL_OUTPUT_DIR}/runtime"
  LOCAL_SECRETS_FILE="${LOCAL_RUNTIME_DIR}/secrets.env"
	LOCAL_COMPOSE_FILE="${LOCAL_OUTPUT_DIR}/docker-compose.yml"
	LOCAL_CONFIG_FILE="${LOCAL_OUTPUT_DIR}/config.local.yaml"
	LOCAL_DASHBOARD_ENV_FILE="${LOCAL_OUTPUT_DIR}/dashboard.local.env"
	LOCAL_TRAEFIK_FILE="${LOCAL_OUTPUT_DIR}/traefik.local.yaml"
	LOCAL_LDAP_BOOTSTRAP_FILE="${LOCAL_OUTPUT_DIR}/ldap-bootstrap.local.ldif"
  LOCAL_TLS_DIR="${LOCAL_RUNTIME_DIR}/tls"
  LOCAL_TLS_CERT_FILE="${LOCAL_TLS_DIR}/netbird.crt"
  LOCAL_TLS_KEY_FILE="${LOCAL_TLS_DIR}/netbird.key"
  LOCAL_LDAP_TLS_DIR="${LOCAL_RUNTIME_DIR}/ldap-tls"
  LOCAL_LDAP_CA_CERT_FILE="${LOCAL_LDAP_TLS_DIR}/ca.crt"
  LOCAL_LDAP_CA_KEY_FILE="${LOCAL_LDAP_TLS_DIR}/ca.key"
  LOCAL_LDAP_CERT_FILE="${LOCAL_LDAP_TLS_DIR}/ldap.crt"
  LOCAL_LDAP_KEY_FILE="${LOCAL_LDAP_TLS_DIR}/ldap.key"
  LOCAL_TUNNEL_DOMAIN_FILE="${LOCAL_RUNTIME_DIR}/quick-tunnel-domain"
  LOCAL_DOMAIN="${NETBIRD_DOMAIN:-}"
  LOCAL_CLIENT_ENDPOINT="${NETBIRD_CLIENT_ENDPOINT:-}"
  LOCAL_BIND_IP="${NETBIRD_BIND_IP:-$(get_main_ip_address)}"
  LOCAL_STUN_PORT="${NETBIRD_STUN_PORT:-3478}"
  LOCAL_IMAGE_PREFIX="${NETBIRD_LOCAL_IMAGE_PREFIX:-netbird-local}"
  LOCAL_PROJECT_NAME="${NETBIRD_COMPOSE_PROJECT:-netbird-local}"
  LOCAL_ACTION="${NETBIRD_LOCAL_ACTION:-deploy}"
  LOCAL_QUICK_TUNNEL="${NETBIRD_QUICK_TUNNEL:-false}"
  LOCAL_QUICK_TUNNEL_LAN_ACCESS="${NETBIRD_QUICK_TUNNEL_LAN_ACCESS:-false}"
  LOCAL_TLS_MODE="${NETBIRD_TLS_MODE:-auto}"
	LOCAL_DEPLOYMENT_MODE="${NETBIRD_DEPLOYMENT_MODE:-production}"
	LOCAL_BOOTSTRAP_TEST_USERS="${NETBIRD_BOOTSTRAP_TEST_USERS:-false}"
  LOCAL_CLOUDFLARED_IMAGE="${NETBIRD_CLOUDFLARED_IMAGE:-cloudflare/cloudflared:2026.7.2}"
  LOCAL_TUNNEL_CONTAINER="${LOCAL_PROJECT_NAME}-cloudflared"
  LOCAL_TUNNEL_BOOTSTRAP_NETWORK="${LOCAL_PROJECT_NAME}-tunnel-bootstrap"
  LOCAL_COMPOSE_NETWORK="${LOCAL_PROJECT_NAME}_netbird"
  LOCAL_NETWORK_SUBNET="${NETBIRD_NETWORK_SUBNET:-172.31.250.0/24}"
  LOCAL_TRAEFIK_IP="${NETBIRD_TRAEFIK_IP:-172.31.250.10}"
	LOCAL_TRAEFIK_MEMORY_LIMIT="${NETBIRD_TRAEFIK_MEMORY_LIMIT:-256m}"
	LOCAL_DASHBOARD_MEMORY_LIMIT="${NETBIRD_DASHBOARD_MEMORY_LIMIT:-512m}"
	LOCAL_SERVER_MEMORY_LIMIT="${NETBIRD_SERVER_MEMORY_LIMIT:-2g}"
	LOCAL_POSTGRES_MEMORY_LIMIT="${NETBIRD_POSTGRES_MEMORY_LIMIT:-2g}"
	LOCAL_LDAP_MEMORY_LIMIT="${NETBIRD_LDAP_MEMORY_LIMIT:-512m}"
	export LOCAL_TRAEFIK_MEMORY_LIMIT LOCAL_DASHBOARD_MEMORY_LIMIT LOCAL_SERVER_MEMORY_LIMIT \
	  LOCAL_POSTGRES_MEMORY_LIMIT LOCAL_LDAP_MEMORY_LIMIT

  if [[ "$LOCAL_ACTION" != "deploy" && "$LOCAL_ACTION" != "render" && "$LOCAL_ACTION" != "build" && "$LOCAL_ACTION" != "down" ]]; then
    echo "NETBIRD_LOCAL_ACTION must be 'deploy', 'render', 'build', or 'down'." > /dev/stderr
    exit 1
  fi
	if [[ "$LOCAL_DEPLOYMENT_MODE" != "production" && "$LOCAL_DEPLOYMENT_MODE" != "development" ]]; then
	  echo "NETBIRD_DEPLOYMENT_MODE must be 'production' or 'development'." > /dev/stderr
	  exit 1
	fi
	if [[ "$LOCAL_BOOTSTRAP_TEST_USERS" != "true" && "$LOCAL_BOOTSTRAP_TEST_USERS" != "false" ]]; then
	  echo "NETBIRD_BOOTSTRAP_TEST_USERS must be 'true' or 'false'." > /dev/stderr
	  exit 1
	fi
  if [[ "$LOCAL_QUICK_TUNNEL" != "true" && "$LOCAL_QUICK_TUNNEL" != "false" ]]; then
    echo "NETBIRD_QUICK_TUNNEL must be 'true' or 'false'." > /dev/stderr
    exit 1
  fi
  if [[ "$LOCAL_QUICK_TUNNEL_LAN_ACCESS" != "true" && "$LOCAL_QUICK_TUNNEL_LAN_ACCESS" != "false" ]]; then
    echo "NETBIRD_QUICK_TUNNEL_LAN_ACCESS must be 'true' or 'false'." > /dev/stderr
    exit 1
  fi
  if [[ "$LOCAL_QUICK_TUNNEL_LAN_ACCESS" == "true" && "$LOCAL_QUICK_TUNNEL" != "true" ]]; then
    echo "NETBIRD_QUICK_TUNNEL_LAN_ACCESS=true requires NETBIRD_QUICK_TUNNEL=true." > /dev/stderr
    exit 1
  fi
	if [[ "$LOCAL_DEPLOYMENT_MODE" == "production" && "$LOCAL_QUICK_TUNNEL" == "true" ]]; then
	  echo "Cloudflare Quick Tunnel is temporary and cannot be used in production mode." > /dev/stderr
	  exit 1
	fi
	if [[ "$LOCAL_DEPLOYMENT_MODE" == "production" && "$LOCAL_BOOTSTRAP_TEST_USERS" == "true" ]]; then
	  echo "Production mode refuses to create deterministic LDAP test accounts." > /dev/stderr
	  exit 1
	fi

  cd "$LOCAL_SCRIPT_DIR" || exit 1
  local_detect_compose
  check_docker_sock_perms
	local_acquire_deployment_lock
  if [[ "$LOCAL_ACTION" == "down" ]]; then
    local_stop_deployment
    return 0
  fi
  local_resolve_main_commit
	if [[ "$LOCAL_ACTION" == "build" ]]; then
	  local_build_images || return 1
	  return 0
	fi
  local_resolve_domain_and_tls_mode
  if [[ "$LOCAL_QUICK_TUNNEL" == "true" ]]; then
    local_start_quick_tunnel
  fi
  local_validate_domain_and_network
  local_prepare_secrets
  local_render_ldap_bootstrap
  local_prepare_tls_certificate
  local_prepare_ldap_tls_certificate
  local_ensure_hosts_entry
  local_render_server_config
  local_render_dashboard_env
  local_render_traefik_config
  local_render_compose

  LOCAL_COMPOSE=("${LOCAL_COMPOSE_BIN[@]}" --project-name "$LOCAL_PROJECT_NAME" --env-file "$LOCAL_SECRETS_FILE" -f "$LOCAL_COMPOSE_FILE")

  echo "Validating generated Compose configuration..."
  "${LOCAL_COMPOSE[@]}" config --quiet

  if [[ "$LOCAL_ACTION" == "render" ]]; then
    echo "Local configuration rendered and validated: ${LOCAL_COMPOSE_FILE}"
    return 0
  fi

  local build_options=(build)
  if [[ "${NETBIRD_BUILD_PULL:-false}" == "true" ]]; then
    build_options+=(--pull)
  fi
  if [[ "${NETBIRD_BUILD_NO_CACHE:-false}" == "true" ]]; then
    build_options+=(--no-cache)
  fi

  echo "Building local NetBird server ${LOCAL_IMAGE_VERSION} and dashboard ${LOCAL_DASHBOARD_IMAGE_VERSION}..."
  "${LOCAL_COMPOSE[@]}" "${build_options[@]}" dashboard netbird-server

  local local_services=(postgres openldap netbird-server dashboard traefik)
  if [[ -n "$LOCAL_CLIENT_PROXY_PORT" ]]; then
    local_services+=(client-proxy)
  fi
  echo "Starting PostgreSQL, OpenLDAP, local NetBird images, Traefik, and optional client proxy..."
  "${LOCAL_COMPOSE[@]}" up -d --remove-orphans "${local_services[@]}"
  if [[ "$LOCAL_QUICK_TUNNEL" == "true" ]]; then
    local_attach_quick_tunnel
  fi

  local_wait_for_service postgres
  local_wait_for_service openldap
  local_sync_ldap_bootstrap_passwords
  local_wait_for_service netbird-server
  local_wait_for_service dashboard
  local_wait_for_service traefik
  if [[ -n "$LOCAL_CLIENT_PROXY_PORT" ]]; then
    local_wait_for_service client-proxy
  fi
  local_run_container_smoke_tests
  local_run_quick_tunnel_smoke_tests

  echo ""
  echo "Local NetBird deployment is ready."
  echo "  URL:              ${LOCAL_BASE_URL}"
  if [[ "$LOCAL_CLIENT_ENDPOINT" != "$LOCAL_BASE_URL" ]]; then
    echo "  Client endpoint:  ${LOCAL_CLIENT_ENDPOINT}"
  fi
  if [[ "$LOCAL_QUICK_TUNNEL" == "true" ]]; then
    echo "  Exposure:         temporary public Cloudflare Quick Tunnel"
    if [[ "$LOCAL_QUICK_TUNNEL_LAN_ACCESS" == "true" ]]; then
      echo "  LAN origin:       ${LOCAL_BIND_IP}:443 (local hosts override)"
    fi
  else
    echo "  LAN IP:           ${LOCAL_BIND_IP}"
  fi
  echo "  Main commit:      ${LOCAL_MAIN_COMMIT_ID}"
  echo "  Server version:   ${LOCAL_IMAGE_VERSION}"
  echo "  Dashboard commit: ${LOCAL_DASHBOARD_MAIN_COMMIT_ID}"
  echo "  Dashboard version: ${LOCAL_DASHBOARD_IMAGE_VERSION}"
  echo "  Server image:     ${LOCAL_IMAGE_PREFIX}/netbird-server:${LOCAL_IMAGE_VERSION}"
  echo "  Dashboard image:  ${LOCAL_IMAGE_PREFIX}/dashboard:${LOCAL_DASHBOARD_IMAGE_VERSION}"
  if [[ "$LOCAL_TLS_MODE" == "letsencrypt" ]]; then
    echo "  TLS certificate:  Let's Encrypt (Traefik automatic renewal)"
  else
    echo "  Origin TLS cert:  ${LOCAL_TLS_CERT_FILE} (container-generated)"
  fi
  echo "  Admin email:      admin@${LOCAL_DOMAIN}"
  echo "  Secrets file:     ${LOCAL_SECRETS_FILE}"
	if [[ "$LOCAL_BOOTSTRAP_TEST_USERS" == "true" ]]; then
	  echo "  LDAP test users:  ldapuser@example.org, ldapadmin@example.org"
	  echo "  LDAP passwords:   LDAP_BOOTSTRAP_* entries in ${LOCAL_SECRETS_FILE}"
	else
	  echo "  LDAP test users:  disabled (production default)"
	fi
  echo "  Stop command:     NETBIRD_LOCAL_ACTION=down bash ${LOCAL_SCRIPT_DIR}/getting-started-local.sh"
  "${LOCAL_COMPOSE[@]}" ps
}

if [[ "${NETBIRD_LOCAL_DEVELOPMENT:-true}" != "true" ]]; then
  echo "NETBIRD_LOCAL_DEVELOPMENT=false is no longer supported; this script has one canonical source-build production path." > /dev/stderr
  exit 1
fi
run_local_source_deployment
