#!/usr/bin/env bash
set -euo pipefail




RED=$(tput setaf 1); GREEN=$(tput setaf 2); YELLOW=$(tput setaf 3); RESET=$(tput sgr0)

say() { echo "${GREEN}[+]${RESET} $*"; }
warn() { echo "${YELLOW}[!]${RESET} $*"; }
err() { echo "${RED}[-]${RESET} $*"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "Required command '$1' not found"; exit 1; }
}

require_cmd curl
require_cmd unzip

TOOLS_DIR="${TOOLS_DIR:-$HOME/.local/android-tools}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$TOOLS_DIR" "$BIN_DIR"


APKTOOL_JAR="${TOOLS_DIR}/apktool_2.9.3.jar"
if [[ ! -f "$APKTOOL_JAR" ]]; then
  say "Downloading apktool..."
  curl -fsSL -o "$APKTOOL_JAR" https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar
  printf '#!/usr/bin/env bash\nexec java -jar "%s" "$@"\n' "$APKTOOL_JAR" > "$BIN_DIR/apktool"
  chmod +x "$BIN_DIR/apktool"
else
  say "apktool already present"
fi


JADX_DIR="${TOOLS_DIR}/jadx-1.5.0"
if [[ ! -d "$JADX_DIR" ]]; then
  say "Downloading jadx..."
  curl -fsSL -o "$TOOLS_DIR/jadx.zip" https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip
  unzip -q -o "$TOOLS_DIR/jadx.zip" -d "$TOOLS_DIR"
  ln -sf "$JADX_DIR/bin/jadx" "$BIN_DIR/jadx"
  ln -sf "$JADX_DIR/bin/jadx-gui" "$BIN_DIR/jadx-gui"
else
  say "jadx already present"
fi


UAS_JAR="${TOOLS_DIR}/uber-apk-signer-1.3.0.jar"
if [[ ! -f "$UAS_JAR" ]]; then
  say "Downloading uber-apk-signer..."
  curl -fsSL -o "$UAS_JAR" https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar
  printf '#!/usr/bin/env bash\nexec java -jar "%s" "$@"\n' "$UAS_JAR" > "$BIN_DIR/uber-apk-signer"
  chmod +x "$BIN_DIR/uber-apk-signer"
else
  say "uber-apk-signer already present"
fi


if ! command -v adb >/dev/null 2>&1; then
  say "Installing platform-tools (adb)..."
  PT_ZIP="$TOOLS_DIR/platform-tools-linux.zip"
  curl -fsSL -o "$PT_ZIP" https://dl.google.com/android/repository/platform-tools-latest-linux.zip
  unzip -q -o "$PT_ZIP" -d "$TOOLS_DIR"
  ln -sf "$TOOLS_DIR/platform-tools/adb" "$BIN_DIR/adb"
  ln -sf "$TOOLS_DIR/platform-tools/fastboot" "$BIN_DIR/fastboot"
else
  say "adb already present in PATH"
fi

say "Done. Ensure ${BIN_DIR} is in your PATH."
