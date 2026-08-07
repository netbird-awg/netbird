#!/bin/sh

export PATH="$PATH":/usr/local/bin:/opt/homebrew/bin

# Stop the legacy daemon before installing the renamed service.
LEGACY_NB_BIN=$(command -v netbird || true)
if [ -n "$LEGACY_NB_BIN" ]
then
  echo "Stopping and uninstalling legacy NetBird daemon"
  netbird service stop || true
  netbird service uninstall || true
fi

NB_BIN=$(command -v netibird-awg || true)
if [ -z "$NB_BIN" ]
then
  echo "Netibird-AWG daemon is not installed."
  exit 1
fi
NB_UI_VERSION=$1
NB_VERSION=$(netibird-awg version)
if [ "$NB_UI_VERSION" != "$NB_VERSION" ]
then
  echo "Netibird-AWG daemon and UI versions differ:"
  echo "Netibird-AWG UI Version: $NB_UI_VERSION"
  echo "Netibird-AWG Daemon Version: $NB_VERSION"
fi

if [ -n "$NB_BIN" ]
then
  echo "Stopping Netibird-AWG daemon"
  osascript -e 'quit app "Netibird-AWG"' 2> /dev/null || true
  osascript -e 'quit app "Netbird UI"' 2> /dev/null || true
  netibird-awg service stop 2> /dev/null || true
fi

# Start the renamed daemon service.
echo "Starting Netibird-AWG daemon"
netibird-awg service install 2> /dev/null || true
netibird-awg service start || true

# start app
open "/Applications/Netibird-AWG.app"
