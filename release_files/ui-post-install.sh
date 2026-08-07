#!/bin/sh

set -e
set -u

# Restart the renamed UI only when either the current or legacy UI was running.
pid="$(pgrep -f '^/usr/bin/(netibird-awg-ui|netbird-ui)([[:space:]]|$)' | head -n 1 || true)"
if [ -n "${pid}" ]
then
  uid="$(cat /proc/"${pid}"/loginuid)"
  # loginuid can be 4294967295 (-1) if not set, fall back to process uid
  if [ "${uid}" = "4294967295" ] || [ "${uid}" = "-1" ]; then
    uid="$(stat -c '%u' /proc/"${pid}")"
  fi
  username="$(id -nu "${uid}")"
  # Only re-run if it was already running
  pkill -f '^/usr/bin/(netibird-awg-ui|netbird-ui)([[:space:]]|$)' >/dev/null 2>&1 || true
  su - "${username}" -c 'nohup /usr/bin/netibird-awg-ui > /dev/null 2>&1 &'
fi
