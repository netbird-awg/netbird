#!/bin/sh

# Step 1, decide if we should use systemd or init/upstart
use_systemctl="True"
if ! command -V systemctl >/dev/null 2>&1; then
  use_systemctl="False"
fi

cleanInstall() {
    printf "\033[32m Post Install of an clean install\033[0m\n"
    # Step 3 (clean install), enable the service in the proper way for this platform
    /usr/bin/netibird-awg service install
    /usr/bin/netibird-awg service start
}

upgrade() {
    printf "\033[32m Post Install of an upgrade\033[0m\n"
    if [ "${use_systemctl}" = "True" ]; then
      printf "\033[32m Stopping the service\033[0m\n"
      systemctl stop netbird 2> /dev/null || true
      systemctl stop netibird-awg 2> /dev/null || true
    fi
    if [ -e /lib/systemd/system/netbird.service ]; then
      rm -f /lib/systemd/system/netbird.service
      systemctl daemon-reload
    fi
    # will trow an error until everyone upgrade
    if [ -x /usr/bin/netbird ]; then
      /usr/bin/netbird service uninstall 2> /dev/null || true
    fi
    /usr/bin/netibird-awg --service netbird service uninstall 2> /dev/null || true
    /usr/bin/netibird-awg service install
    /usr/bin/netibird-awg service start
}

# Check if this is a clean install or an upgrade
action="$1"
if  [ "$1" = "configure" ] && [ -z "$2" ]; then
  # Alpine linux does not pass args, and deb passes $1=configure
  action="install"
elif [ "$1" = "configure" ] && [ -n "$2" ]; then
    # deb passes $1=configure $2=<current version>
    action="upgrade"
fi

case "$action" in
  "1" | "install")
    cleanInstall
    ;;
  "2" | "upgrade")
    upgrade
    ;;
  *)
    cleanInstall
    ;;
esac
