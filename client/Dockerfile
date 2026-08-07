# build & run locally with:
#   cd "$(git rev-parse --show-toplevel)"
#   CGO_ENABLED=0 go build -o netibird-awg ./client
#   sudo podman build -t localhost/netibird-awg:latest -f client/Dockerfile --ignorefile .dockerignore-client .
#   sudo podman run --rm -it --cap-add={BPF,NET_ADMIN,NET_RAW} localhost/netibird-awg:latest

FROM alpine:3.24
# iproute2: busybox doesn't display ip rules properly
RUN apk add --no-cache \
    bash \
    ca-certificates \
    ip6tables \
    iproute2 \
    iptables

ENV \
    NETBIRD_BIN="/usr/local/bin/netibird-awg" \
    NB_LOG_FILE="console,/var/log/netbird/client.log" \
    NB_DAEMON_ADDR="unix:///var/run/netbird.sock" \
    NB_ENABLE_CAPTURE="false" \
    NB_ENTRYPOINT_SERVICE_TIMEOUT="30"

ENTRYPOINT [ "/usr/local/bin/netibird-awg-entrypoint.sh" ]
ARG TARGETPLATFORM
ARG NETBIRD_BINARY=$TARGETPLATFORM/netibird-awg
COPY client/netibird-awg-entrypoint.sh /usr/local/bin/netibird-awg-entrypoint.sh
COPY "${NETBIRD_BINARY}" /usr/local/bin/netibird-awg
