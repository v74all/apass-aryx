#!/usr/bin/env bash
set -euo pipefail





BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"


ARCH=${1:-android-x86_64}
SERIAL_FLAG=()
AUTO_DOWNLOAD=false
VERBOSE=false


shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    -s|--serial)
      SERIAL_FLAG=(-s "$2")
      shift 2
      ;;
    --download)
      AUTO_DOWNLOAD=true
      shift
      ;;
    -v|--verbose)
      VERBOSE=true
      shift
      ;;
    *)
      SERIAL_FLAG=(-s "$1")
      shift
      ;;
  esac
done

log_info() { echo -e "${BLUE}[INFO]${RESET} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${RESET} $1"; }
log_warn() { echo -e "${YELLOW}[WARNING]${RESET} $1"; }
log_error() { echo -e "${RED}[ERROR]${RESET} $1"; }

if [[ "$VERBOSE" == "true" ]]; then
  log_info "Running Frida Manager with arch: $ARCH"
  [[ ${#SERIAL_FLAG[@]} -gt 0 ]] && log_info "Device serial: ${SERIAL_FLAG[1]}"
fi



SCRIPT_SOURCE="${BASH_SOURCE[0]:-$0}"
SCRIPT_DIR="$(cd -- "$(dirname -- "$SCRIPT_SOURCE")" >/dev/null 2>&1 && pwd)"

REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"
BIN_DIR_DEFAULT="$REPO_ROOT/resources/binaries"


if [[ -n "${FRIDA_BIN_DIR:-}" && -d "$FRIDA_BIN_DIR" ]]; then
  BIN_DIR="$FRIDA_BIN_DIR"
elif [[ -d "$BIN_DIR_DEFAULT" ]]; then
  BIN_DIR="$BIN_DIR_DEFAULT"
else

  BIN_DIR="$(cd -- "$(dirname -- "$SCRIPT_SOURCE")/../../resources/binaries" >/dev/null 2>&1 && pwd || true)"
fi

if [[ -z "${BIN_DIR:-}" || ! -d "$BIN_DIR" ]]; then
  log_error "Could not locate binaries directory. Tried: '$BIN_DIR_DEFAULT' and legacy path."
  exit 1
fi


detect_frida_binary() {
  local arch="$1"
  local best=""
  if compgen -G "${BIN_DIR}/frida-server-*-${arch}" >/dev/null; then

    best=$(ls -1 ${BIN_DIR}/frida-server-*-${arch} | sort -V | tail -n1)
  fi
  echo "$best"
}


detect_frida_version() {
  if command -v frida >/dev/null 2>&1; then
    frida --version 2>/dev/null | awk '{print $1}'
  else
    echo ""
  fi
}

FRIDA_BIN="$(detect_frida_binary "$ARCH")"
FRIDA_VERSION="$(detect_frida_version)"
[[ -z "$FRIDA_VERSION" ]] && FRIDA_VERSION="17.2.17" # sensible default matching requirements


if ! adb ${SERIAL_FLAG[@]+"${SERIAL_FLAG[@]}"} get-state &>/dev/null; then
  log_error "No device connected or device is not authorized"
  log_info "Run 'adb devices' to see available devices"
  exit 1
fi


if [[ -z "$FRIDA_BIN" || ! -f "$FRIDA_BIN" ]]; then
  if [[ "$AUTO_DOWNLOAD" == "true" ]]; then
  log_info "Frida binary not found. Attempting to download version $FRIDA_VERSION for $ARCH..."
    

    mkdir -p "$BIN_DIR"
    

  DOWNLOAD_URL="https://github.com/frida/frida/releases/download/$FRIDA_VERSION/frida-server-$FRIDA_VERSION-$ARCH.xz"
    

    TMP_BIN="${BIN_DIR}/frida-server-${FRIDA_VERSION}-${ARCH}"
    if curl -L "$DOWNLOAD_URL" -o "${TMP_BIN}.xz" && xz -d "${TMP_BIN}.xz"; then
      chmod +x "$TMP_BIN"
      FRIDA_BIN="$TMP_BIN"
      log_success "Downloaded and extracted frida-server $FRIDA_VERSION for $ARCH"
    else
      log_error "Failed to download frida-server"
      log_info "Please download manually from: https://github.com/frida/frida/releases"
      exit 1
    fi
  else
    log_error "Frida binary not found for ${ARCH} in ${BIN_DIR}"
    log_info "Use --download flag to attempt automatic download"
    exit 1
  fi
fi


if adb ${SERIAL_FLAG[@]+"${SERIAL_FLAG[@]}"} root >/dev/null 2>&1; then
  log_info "Successfully got root access on device"
else
  log_warn "Could not get root access on device, attempting to continue anyway"
fi


log_info "Pushing frida-server to device..."
if ! adb ${SERIAL_FLAG[@]+"${SERIAL_FLAG[@]}"} push "$FRIDA_BIN" /data/local/tmp/frida-server; then
  log_error "Failed to push frida-server to device"
  exit 1
fi


if adb ${SERIAL_FLAG[@]+"${SERIAL_FLAG[@]}"} shell "ps -ef | grep frida-server | grep -v grep" &>/dev/null; then
  log_warn "frida-server is already running, killing previous instance..."
  adb ${SERIAL_FLAG[@]+"${SERIAL_FLAG[@]}"} shell "killall frida-server" &>/dev/null || true
  sleep 1
fi


if adb ${SERIAL_FLAG[@]+"${SERIAL_FLAG[@]}"} shell 'command -v su >/dev/null 2>&1'; then
  log_info "Using su to start frida-server with root privileges"
  adb ${SERIAL_FLAG[@]+"${SERIAL_FLAG[@]}"} shell su -c 'chmod 755 /data/local/tmp/frida-server'
  adb ${SERIAL_FLAG[@]+"${SERIAL_FLAG[@]}"} shell su -c 'nohup /data/local/tmp/frida-server -D >/data/local/tmp/frida.log 2>&1 &'
else
  log_info "Starting frida-server without su"
  adb ${SERIAL_FLAG[@]+"${SERIAL_FLAG[@]}"} shell 'chmod 755 /data/local/tmp/frida-server'
  adb ${SERIAL_FLAG[@]+"${SERIAL_FLAG[@]}"} shell 'nohup /data/local/tmp/frida-server -D >/data/local/tmp/frida.log 2>&1 &'
fi


sleep 2
if adb ${SERIAL_FLAG[@]+"${SERIAL_FLAG[@]}"} shell "ps -ef | grep frida-server | grep -v grep" &>/dev/null; then
  log_success "frida-server started successfully!"
  log_info "Log (if accessible): /data/local/tmp/frida.log"
  

  log_info "Setting up port forwarding for Frida (27042 -> 27042)..."
  adb ${SERIAL_FLAG[@]+"${SERIAL_FLAG[@]}"} forward tcp:27042 tcp:27042
  

  if command -v frida-ps &>/dev/null; then
    if frida-ps -U &>/dev/null; then
      log_success "Frida connection verified. Ready for debugging!"
    else
      log_warn "Frida is running but connection test failed. Check USB debugging."
    fi
  fi
else
  log_error "Failed to start frida-server. Check device logs."
  exit 1
fi
