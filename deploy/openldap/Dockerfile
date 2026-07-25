FROM debian:13-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates ldap-utils slapd tini util-linux && \
    rm -rf /var/lib/apt/lists/* /var/lib/ldap/* /etc/ldap/slapd.d/* && \
    install -d -o openldap -g openldap /var/lib/ldap /run/slapd

COPY entrypoint.sh /usr/local/bin/netbird-openldap-entrypoint
RUN chmod 0755 /usr/local/bin/netbird-openldap-entrypoint

EXPOSE 636
VOLUME ["/var/lib/ldap"]
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/netbird-openldap-entrypoint"]
