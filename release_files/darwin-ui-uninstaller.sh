#!/bin/sh

export PATH="$PATH":/usr/local/bin

# Keep the daemon installed when removing only the UI.
NB_BIN=$(command -v netibird-awg || true)
if [ -z "$NB_BIN" ]
then
  exit 0
fi
echo "Netibird-AWG daemon service is still running. You can uninstall it with:"
echo "sudo netibird-awg service stop"
echo "sudo netibird-awg service uninstall"
