#!/bin/sh
set -eu

: "${LDAP_BASE_DN:?LDAP_BASE_DN is required}"
: "${LDAP_ADMIN_PASSWORD:?LDAP_ADMIN_PASSWORD is required}"
: "${LDAP_TLS_CERT_FILE:?LDAP_TLS_CERT_FILE is required}"
: "${LDAP_TLS_KEY_FILE:?LDAP_TLS_KEY_FILE is required}"
: "${LDAP_TLS_CA_FILE:?LDAP_TLS_CA_FILE is required}"

data_dir=/var/lib/ldap
runtime_dir=/run/slapd
config_file="${runtime_dir}/slapd.conf"
bootstrap_file="${LDAP_BOOTSTRAP_FILE:-/bootstrap/custom.ldif}"
root_dn="cn=admin,${LDAP_BASE_DN}"
base_dc=$(printf '%s' "$LDAP_BASE_DN" | sed -n 's/^dc=\([^,]*\).*/\1/p')

if [ -z "$base_dc" ]; then
  echo "LDAP_BASE_DN must begin with dc=" >&2
  exit 1
fi

install -d -m 0750 -o openldap -g openldap "$runtime_dir" "$data_dir"
install -m 0644 -o openldap -g openldap "$LDAP_TLS_CERT_FILE" "${runtime_dir}/ldap.crt"
install -m 0600 -o openldap -g openldap "$LDAP_TLS_KEY_FILE" "${runtime_dir}/ldap.key"
install -m 0644 -o openldap -g openldap "$LDAP_TLS_CA_FILE" "${runtime_dir}/ca.crt"

root_password_hash=$(slappasswd -s "$LDAP_ADMIN_PASSWORD")
cat >"$config_file" <<EOF
include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/nis.schema
include /etc/ldap/schema/inetorgperson.schema

pidfile ${runtime_dir}/slapd.pid
argsfile ${runtime_dir}/slapd.args
modulepath /usr/lib/ldap
moduleload back_mdb

TLSCertificateFile ${runtime_dir}/ldap.crt
TLSCertificateKeyFile ${runtime_dir}/ldap.key
TLSCACertificateFile ${runtime_dir}/ca.crt
TLSProtocolMin 3.3

database mdb
maxsize 1073741824
suffix "${LDAP_BASE_DN}"
rootdn "${root_dn}"
rootpw ${root_password_hash}
directory ${data_dir}
index objectClass eq
index uid,mail,cn eq,sub

access to attrs=userPassword
  by self write
  by anonymous auth
  by dn.exact="${root_dn}" write
  by * none
access to *
  by dn.exact="${root_dn}" write
  by users read
  by anonymous auth
EOF
chown openldap:openldap "$config_file"
chmod 0600 "$config_file"

if ! find "$data_dir" -mindepth 1 -maxdepth 1 -type f | grep -q .; then
  base_ldif="${runtime_dir}/base.ldif"
  cat >"$base_ldif" <<EOF
dn: ${LDAP_BASE_DN}
objectClass: top
objectClass: dcObject
objectClass: organization
o: NetBird Local
dc: ${base_dc}
EOF
  slapadd -f "$config_file" -l "$base_ldif"
  if [ -s "$bootstrap_file" ]; then
    slapadd -f "$config_file" -l "$bootstrap_file"
  fi
fi

chown -R openldap:openldap "$data_dir" "$runtime_dir"

exec setpriv \
  --reuid=openldap \
  --regid=openldap \
  --init-groups \
  slapd -d 0 -f "$config_file" -h "${LDAP_LISTEN_URIS:-ldaps:/// ldapi:///}"
