#!/bin/sh

export PATH="$PATH":/usr/local/bin:/opt/homebrew/bin

NB_BIN=$(command -v netibird-awg || true)
if [ -z "$NB_BIN" ]
then
  echo "NetBird-AWG daemon is not installed."
  exit 1
fi
NB_UI_VERSION=$1
NB_VERSION=$(netibird-awg version)
if [ "$NB_UI_VERSION" != "$NB_VERSION" ]
then
  echo "NetBird-AWG daemon and UI versions differ:"
  echo "NetBird-AWG UI Version: $NB_UI_VERSION"
  echo "NetBird-AWG Daemon Version: $NB_VERSION"
fi

if [ -n "$NB_BIN" ]
then
  echo "Stopping NetBird-AWG daemon"
  osascript -e 'quit app "NetBird-AWG"' 2> /dev/null || true
  netibird-awg service stop 2> /dev/null || true
fi

# Start the renamed daemon service.
echo "Starting NetBird-AWG daemon"
netibird-awg service install 2> /dev/null || true
netibird-awg service start || true

# start app
open "/Applications/NetBird-AWG.app"
