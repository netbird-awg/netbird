#!/usr/bin/env bash
# This code is based on the netbird-installer contribution by physk on GitHub.
# Source: https://github.com/physk/netbird-installer
set -e

CONFIG_FOLDER="/etc/netbird"
CONFIG_FILE="$CONFIG_FOLDER/install.conf"

OWNER="netbird-awg"
REPO="netbird"
CLI_APP="netibird-awg"
UI_APP="netibird-awg-ui"

# Set default variable
OS_NAME=""
OS_TYPE=""
ARCH="$(uname -m)"
PACKAGE_MANAGER="bin"
INSTALL_DIR=""
SUDO=""
# Fork releases are distributed from GitHub; upstream package repositories do
# not carry the renamed binaries.
USE_BIN_INSTALL=true


if command -v sudo > /dev/null && [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
elif command -v doas > /dev/null && [ "$(id -u)" -ne 0 ]; then
    SUDO="doas"
fi

if [ -z ${NETBIRD_RELEASE+x} ]; then
    NETBIRD_RELEASE=latest
fi

TAG_NAME=""

get_release() {
    local RELEASE=$1
    if [ "$RELEASE" = "latest" ]; then
        local TAG="latest"
        local URL="https://api.github.com/repos/${OWNER}/${REPO}/releases/latest"
    else
        local TAG="tags/${RELEASE}"
        local URL="https://api.github.com/repos/${OWNER}/${REPO}/releases/${TAG}"
    fi
	OUTPUT=""
    if [ -n "$GITHUB_TOKEN" ]; then
          OUTPUT=$(curl -H  "Authorization: token ${GITHUB_TOKEN}" -s "${URL}")
    else
          OUTPUT=$(curl -s "${URL}") 
    fi
	TAG_NAME=$(echo "${OUTPUT}" | grep -Eo '\"tag_name\":\s*\"v([0-9]+\.){2}[0-9]+"' | tail -n 1)
	echo "${TAG_NAME}" | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+'
}

download_release_binary() {
    VERSION=$(get_release "$NETBIRD_RELEASE")
	echo "Using the following tag name for binary installation: ${TAG_NAME}"
    BASE_URL="https://github.com/${OWNER}/${REPO}/releases/download"
    if [ "$1" = "$UI_APP" ]; then
       if [ "$OS_TYPE" = "darwin" ]; then
         BINARY_NAME="${UI_APP}_${VERSION#v}_darwin_all.tar.gz"
       else
         BINARY_NAME="${UI_APP}-linux_${VERSION#v}_${OS_TYPE}_${ARCH}.tar.gz"
       fi
    else
       BINARY_NAME="${CLI_APP}_${VERSION#v}_${OS_TYPE}_${ARCH}.tar.gz"
    fi

    DOWNLOAD_URL="${BASE_URL}/${VERSION}/${BINARY_NAME}"

    echo "Installing $1 from $DOWNLOAD_URL"
    if [ -n "$GITHUB_TOKEN" ]; then
      cd /tmp && curl -H  "Authorization: token ${GITHUB_TOKEN}" -LO "$DOWNLOAD_URL"
    else
      cd /tmp
      if ! curl -LO "$DOWNLOAD_URL"; then
        curl -LO --dns-servers 8.8.8.8 "$DOWNLOAD_URL"
      fi
    fi


    ${SUDO} mkdir -p "$INSTALL_DIR"
    tar -xzvf "$BINARY_NAME"
    ${SUDO} mv "$1" "$INSTALL_DIR/"
}

add_apt_repo() {
    ${SUDO} apt-get update
    ${SUDO} apt-get install ca-certificates curl gnupg -y

    # Remove old keys and repo source files
    ${SUDO} rm -f \
        /etc/apt/sources.list.d/netbird.list \
        /etc/apt/sources.list.d/wiretrustee.list \
        /etc/apt/trusted.gpg.d/wiretrustee.gpg \
        /usr/share/keyrings/netbird-archive-keyring.gpg \
        /usr/share/keyrings/wiretrustee-archive-keyring.gpg

    curl -sSL https://pkgs.netbird.io/debian/public.key \
    | ${SUDO} gpg --dearmor -o /usr/share/keyrings/netbird-archive-keyring.gpg

    # Explicitly set the file permission
    ${SUDO} chmod 0644 /usr/share/keyrings/netbird-archive-keyring.gpg

    echo 'deb [signed-by=/usr/share/keyrings/netbird-archive-keyring.gpg] https://pkgs.netbird.io/debian stable main' \
    | ${SUDO} tee /etc/apt/sources.list.d/netbird.list

    ${SUDO} apt-get update
}

add_rpm_repo() {
cat <<-EOF | ${SUDO} tee /etc/yum.repos.d/netbird.repo
[NetBird]
name=NetBird
baseurl=https://pkgs.netbird.io/yum/
enabled=1
gpgcheck=1
gpgkey=https://pkgs.netbird.io/yum/repodata/repomd.xml.key
repo_gpgcheck=1
EOF
}

prepare_tun_module() {
  # Create the necessary file structure for /dev/net/tun
  if [ ! -c /dev/net/tun ]; then
    if [ ! -d /dev/net ]; then
      mkdir -m 755 /dev/net
    fi
    mknod /dev/net/tun c 10 200
    chmod 0755 /dev/net/tun
  fi

  # Load the tun module if not already loaded
  if ! lsmod | grep -q "^tun\s"; then
    insmod /lib/modules/tun.ko
  fi
}

install_native_binaries() {
    # Checks  for supported architecture
    case "$ARCH" in
        x86_64|amd64)
            ARCH="amd64"
        ;;
        i?86|x86)
            ARCH="386"
        ;;
        aarch64|arm64)
            ARCH="arm64"
        ;;
        *)
            echo "Architecture ${ARCH} not supported"
            exit 2
        ;;
    esac

    # download and copy binaries to INSTALL_DIR
    download_release_binary "$CLI_APP"
    if ! $SKIP_UI_APP; then
        download_release_binary "$UI_APP"
    fi
}

# Handle macOS .pkg installer
install_pkg() {
  case "$(uname -m)" in
    x86_64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) echo "Unsupported macOS arch: $(uname -m)" >&2; exit 1 ;;
  esac

  PKG_URL=$(curl -sIL -o /dev/null -w '%{url_effective}' "https://pkgs.netbird.io/macos/${ARCH}")
  echo "Downloading NetBird macOS installer from https://pkgs.netbird.io/macos/${ARCH}"
  curl -fsSL -o /tmp/netbird.pkg "${PKG_URL}"
  ${SUDO} installer -pkg /tmp/netbird.pkg -target /
  rm -f /tmp/netbird.pkg
}

check_use_bin_variable() {
    if [ "${USE_BIN_INSTALL}-x" = "true-x" ]; then
      echo "The installation will be performed using binary files"
      return 0
    fi
    return 1
}

install_netbird() {
    if [ -x "$(command -v netibird-awg)" ]; then
      status_output="$(netibird-awg status 2>&1 || true)"

      if echo "$status_output" | grep -q 'failed to connect to daemon error: context deadline exceeded'; then
          echo "Warning: could not reach Netibird-AWG daemon (timeout), proceeding anyway"
      else
          if echo "$status_output" | grep -q 'Management: Connected' && \
              echo "$status_output" | grep -q 'Signal: Connected'; then
              echo "Netibird-AWG service is running, please stop it before proceeding"
              exit 1
          fi

          if [ -n "$status_output" ]; then
              echo "Netibird-AWG seems to be installed already, please remove it before proceeding"
              exit 1
          fi
      fi
    fi

    # Run the installation, if a desktop environment is not detected
    # only the CLI will be installed
    case "$PACKAGE_MANAGER" in
    apt)
        add_apt_repo
        ${SUDO} apt-get install netbird -y

        if ! $SKIP_UI_APP; then
            ${SUDO} apt-get install netbird-ui -y
        fi
    ;;
    yum)
        add_rpm_repo
        ${SUDO} yum -y install netbird
        if ! $SKIP_UI_APP; then
            ${SUDO} yum -y install netbird-ui
        fi
    ;;
    dnf)
        add_rpm_repo
        ${SUDO} dnf -y install netbird

        if ! $SKIP_UI_APP; then
            ${SUDO} dnf -y install netbird-ui
        fi
    ;;
    rpm-ostree)
        add_rpm_repo
        ${SUDO} rpm-ostree -y install netbird
        if ! $SKIP_UI_APP; then
            ${SUDO} rpm-ostree -y install netbird-ui
        fi
        # ensure the service is started after install
         ${SUDO} netibird-awg service install || true
         ${SUDO} netibird-awg service start || true
    ;;
    pkg)
        # Check if the package is already installed
        if [ -f /Library/Receipts/netbird.pkg ]; then
            echo "NetBird is already installed. Please remove it before proceeding."
            exit 1
        fi

        # Install the package
        install_pkg
    ;;
    brew)
        # Remove Netbird if it had been installed using Homebrew before
        if brew ls --versions netbird >/dev/null 2>&1; then
            echo "Removing existing netbird client"

            # Stop and uninstall daemon service:
            netbird service stop
            netbird service uninstall

            # Unlink the app
            brew unlink netbird
        fi

        brew install netbirdio/tap/netbird
        if ! $SKIP_UI_APP; then
            brew install --cask netbirdio/tap/netbird-ui
        fi
    ;;
    *)
      if [ "$OS_NAME" = "nixos" ];then
        echo "Please add NetBird to your NixOS configuration.nix directly:"
			  echo ""
			  echo "services.netbird.enable = true;"

        if ! $SKIP_UI_APP; then
          echo "environment.systemPackages = [ pkgs.netbird-ui ];"
        fi

        echo "Build and apply new configuration:"
        echo ""
        echo "${SUDO} nixos-rebuild switch"
			  exit 0
      fi

        install_native_binaries
    ;;
    esac

    if [ "$OS_NAME" = "synology" ]; then
        prepare_tun_module
    fi

    # Add package manager to config
    ${SUDO} mkdir -p "$CONFIG_FOLDER"
    echo "package_manager=$PACKAGE_MANAGER" | ${SUDO} tee "$CONFIG_FILE" > /dev/null

    # Load and start netbird service
    if [ "$PACKAGE_MANAGER" != "rpm-ostree" ] && [ "$PACKAGE_MANAGER" != "pkg" ]; then
        if ! ${SUDO} netibird-awg service install 2>&1; then
            echo "Netibird-AWG service has already been loaded"
        fi
        if ! ${SUDO} netibird-awg service start 2>&1; then
            echo "Netibird-AWG service has already been started"
        fi
    fi


    echo "Installation has been finished. To connect, run Netibird-AWG with:"
    echo ""
    echo "netibird-awg up"
}

version_greater_equal() {
    printf '%s\n%s\n' "$2" "$1" | sort -V -c
}

is_bin_package_manager() {
  if ${SUDO} test -f "$1" && ${SUDO} grep -q "package_manager=bin" "$1" ; then
    return 0
  else
    return 1
  fi
}

stop_running_netbird_ui() {
  NB_UI_PROC=$(pgrep -f '(^|/)(netibird-awg-ui|netbird-ui)([[:space:]]|$)' || true)
  if [ -n "$NB_UI_PROC" ]; then
    echo "Netibird-AWG UI is running with PID $NB_UI_PROC. Stopping it..."
    kill -9 "$NB_UI_PROC"
  fi
}

update_netbird() {
  if is_bin_package_manager "$CONFIG_FILE"; then
    latest_release=$(get_release "latest")
    latest_version=${latest_release#v}
    installed_version=$(netibird-awg version)

    if [ "$latest_version" = "$installed_version" ]; then
      echo "Installed Netibird-AWG version ($installed_version) is up-to-date"
      exit 0
    fi

    if version_greater_equal "$latest_version" "$installed_version"; then
      echo "Netibird-AWG new version ($latest_version) available. Updating..."
      echo ""
      echo "Initiating Netibird-AWG update. This will restart the netibird-awg service"

      ${SUDO} netibird-awg service stop || true
      ${SUDO} netibird-awg service uninstall || true
      stop_running_netbird_ui
      install_native_binaries

      ${SUDO} netibird-awg service install
      ${SUDO} netibird-awg service start
    fi
  else
     echo "Netibird-AWG installation was done using a package manager. Please use your system's package manager to update"
  fi
}

# Checks if SKIP_UI_APP env is set
if [ -z "$SKIP_UI_APP" ]; then
    SKIP_UI_APP=false
else
    if $SKIP_UI_APP; then
      echo "SKIP_UI_APP has been set to true in the environment"
      echo "Netibird-AWG UI installation will be omitted based on your preference"
    fi
fi

# Identify OS name and default package manager
if type uname >/dev/null 2>&1; then
	case "$(uname)" in
        Linux)
          OS_TYPE="linux"
          UNAME_OUTPUT="$(uname -a)"
          if echo "$UNAME_OUTPUT" | grep -qi "synology"; then
            OS_NAME="synology"
            INSTALL_DIR="/usr/local/bin"
            PACKAGE_MANAGER="bin"
            SKIP_UI_APP=true
          else
            if [ -f /etc/os-release ]; then
              OS_NAME="$(awk -F= '$1 == "ID" {gsub(/^"|"$/, "", $2); print $2}' /etc/os-release)"
              INSTALL_DIR="/usr/bin"

              # Allow netbird UI installation for x64 arch only
              if [ "$ARCH" != "amd64" ] && [ "$ARCH" != "arm64" ] \
                  && [ "$ARCH" != "x86_64" ];then
                  SKIP_UI_APP=true
                  echo "Netibird-AWG UI installation will be omitted as $ARCH is not a compatible architecture"
              fi

              # Allow netbird UI installation for linux running desktop environment
              if [ -z "$XDG_CURRENT_DESKTOP" ];then
                  SKIP_UI_APP=true
                  echo "Netibird-AWG UI installation will be omitted as Linux does not run desktop environment"
              fi

              # Check the availability of a compatible package manager
              if check_use_bin_variable; then
                  PACKAGE_MANAGER="bin"
              elif [ -e /run/ostree-booted ]; then
                  if [ -x "$(command -v rpm-ostree)" ]; then
                      PACKAGE_MANAGER="rpm-ostree"
                      echo "The installation will be performed using rpm-ostree package manager"
                  elif [ -x "$(command -v bootc)" ]; then
                      echo "Detected bootc system without rpm-ostree." >&2
                      echo "NetBird cannot be installed via package manager on this system." >&2
                      echo "Options:" >&2
                      echo "  1. Install via Distrobox (instructions in the installation docs)" >&2
                      echo "  2. Rebuild your base image with rpm-ostree included" >&2
                      echo "  3. Bake NetBird into your Containerfile" >&2
                      exit 1
                  else
                      echo "Detected ostree-booted system without rpm-ostree or bootc." >&2
                      echo "NetBird cannot be installed automatically on this atomic system." >&2
                      echo "Please install NetBird by rebuilding your base image or use a supported package manager." >&2
                      exit 1
                  fi
              elif [ -x "$(command -v apt-get)" ]; then
                  PACKAGE_MANAGER="apt"
                  echo "The installation will be performed using apt package manager"
              elif [ -x "$(command -v dnf)" ]; then
                  PACKAGE_MANAGER="dnf"
                  echo "The installation will be performed using dnf package manager"
              elif [ -x "$(command -v yum)" ]; then
                  PACKAGE_MANAGER="yum"
                  echo "The installation will be performed using yum package manager"
              fi
            else
              echo "Unable to determine OS type from /etc/os-release"
              exit 1
            fi
          fi


		;;
		Darwin)
            OS_NAME="macos"
			OS_TYPE="darwin"
            INSTALL_DIR="/usr/local/bin"

            # Check the availability of a compatible package manager
            if check_use_bin_variable; then
                PACKAGE_MANAGER="bin"
            else
              PACKAGE_MANAGER="pkg"
            fi
		;;
	esac
fi

UPDATE_FLAG=$1

if [ "${UPDATE_NETBIRD}-x" = "true-x" ]; then
  UPDATE_FLAG="--update"
fi

case "$UPDATE_FLAG" in
    --update)
      update_netbird
    ;;
    *)
      install_netbird
esac
