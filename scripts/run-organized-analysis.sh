#!/usr/bin/env zsh



set -euo pipefail

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DEFAULT_APK_PATH="samples/apps.apk"
DEFAULT_PACKAGE_NAME="com.xnotice.app"


APK_PATH=${1:-$DEFAULT_APK_PATH}
PACKAGE_NAME=${2:-$DEFAULT_PACKAGE_NAME}
VERBOSE=false


for arg in "$@"; do
  case $arg in
    --verbose)
      VERBOSE=true
      ;;
    --apk=*)
      APK_PATH="${arg#*=}"
      ;;
    --package=*)
      PACKAGE_NAME="${arg#*=}"
      ;;
  esac
done


GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'


TOTAL_STEPS=8
CURRENT_STEP=0

print_status() { echo -e "${BLUE}[INFO]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }

show_progress() {
  CURRENT_STEP=$((CURRENT_STEP + 1))
  local percent=$((CURRENT_STEP * 100 / TOTAL_STEPS))
  local progress=$((percent / 2))
  local remaining=$((50 - progress))
  

  local bar="["
  for ((i=0; i<progress; i++)); do bar+="="; done
  if [[ $progress -lt 50 ]]; then bar+=">"; fi
  for ((i=0; i<remaining-1; i++)); do bar+=" "; done
  bar+="]"
  
  echo -e "${CYAN}Step $CURRENT_STEP/$TOTAL_STEPS${NC} $bar ${CYAN}$percent%${NC} - $1"
}


LOG_FILE="logs/analysis_${TIMESTAMP}.log"
mkdir -p "logs"


run_cmd() {
  local cmd="$1"
  local step_desc="$2"
  local output_file="$3"
  
  show_progress "$step_desc"
  

  echo "[COMMAND] $cmd" >> "$LOG_FILE"
  

  if eval "$cmd" > "$output_file" 2>> "$LOG_FILE"; then
    print_success "$step_desc completed"
    return 0
  else
    print_error "$step_desc failed"
    echo "[ERROR] Command failed with exit code $?" >> "$LOG_FILE"
    return 1
  fi
}

print_banner() {
  echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║${NC} ${BOLD}APK Analysis - Organized Workflow${NC}                          ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC} Started: $(date '+%Y-%m-%d %H:%M:%S')                           ${CYAN}║${NC}"
  echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
}

print_banner

print_status "Analysis target: $APK_PATH"
print_status "Package name: $PACKAGE_NAME"
print_status "Log file: $LOG_FILE"

if [[ ! -f "$APK_PATH" ]]; then
    print_error "APK not found at $APK_PATH"
    exit 1
fi


if ! file "$APK_PATH" | grep -q "Zip archive data" && ! file "$APK_PATH" | grep -q "Java archive data"; then
    print_error "The file at $APK_PATH does not appear to be a valid APK file"
    exit 1
fi


SESSION_DIR="analysis_results/sessions/session_${TIMESTAMP}"
mkdir -p "$SESSION_DIR"/{static,dynamic,network,behavioral,logs,extracted,reports}

print_status "Created session directory: $SESSION_DIR"


CONFIG_FILE="config/analysis_config.json"
if [[ -f "$CONFIG_FILE" ]]; then
    print_status "Loading configuration from $CONFIG_FILE"

    if command -v jq &>/dev/null; then
        ENABLE_STATIC=$(jq -r '.analysis.static.enabled // true' < "$CONFIG_FILE")
        ENABLE_DYNAMIC=$(jq -r '.analysis.dynamic.enabled // false' < "$CONFIG_FILE")
        ENABLE_NETWORK=$(jq -r '.analysis.network.enabled // true' < "$CONFIG_FILE")
    else
        print_warning "jq not found, using default configuration"
        ENABLE_STATIC=true
        ENABLE_DYNAMIC=false
        ENABLE_NETWORK=true
    fi
else
    print_warning "Configuration file not found, using default settings"
    ENABLE_STATIC=true
    ENABLE_DYNAMIC=false
    ENABLE_NETWORK=true
fi


if [[ "$ENABLE_STATIC" == "true" ]]; then
    if command -v aapt &>/dev/null; then
        run_cmd "aapt dump badging '$APK_PATH'" "APK Information Extraction" "$SESSION_DIR/static/apk_info.txt"
        

        if [[ "$PACKAGE_NAME" == "$DEFAULT_PACKAGE_NAME" ]]; then
            EXTRACTED_PACKAGE=$(grep "package: name=" "$SESSION_DIR/static/apk_info.txt" | sed -E "s/.*package: name='([^']+).*/\1/")
            if [[ -n "$EXTRACTED_PACKAGE" ]]; then
                PACKAGE_NAME="$EXTRACTED_PACKAGE"
                print_status "Extracted package name: $PACKAGE_NAME"
            fi
        fi
    else
        print_warning "aapt not found, skipping APK information extraction"
    fi
fi


if [[ "$ENABLE_STATIC" == "true" ]]; then
    if [[ -f "tools/python/enhanced_static_analyzer.py" ]]; then
        run_cmd "python3 tools/python/enhanced_static_analyzer.py '$APK_PATH' '$PACKAGE_NAME'" "Static Analysis" "$SESSION_DIR/static/static_analysis.json"
    else
        print_warning "Static analyzer not found, skipping static analysis"
    fi
fi


show_progress "Extracting APK resources"
if command -v apktool &>/dev/null; then
    if apktool d -f -o "$SESSION_DIR/extracted/apktool" "$APK_PATH" >> "$LOG_FILE" 2>&1; then
        print_success "APK resources extracted with apktool"
        

        cp "$SESSION_DIR/extracted/apktool/AndroidManifest.xml" "$SESSION_DIR/static/AndroidManifest.xml" 2>/dev/null || true
    else
        print_warning "Failed to extract APK resources with apktool"
    fi
else
    print_warning "apktool not found, skipping resource extraction"
fi


show_progress "Extracting strings from APK"
if strings "$APK_PATH" > "$SESSION_DIR/static/strings.txt" 2>> "$LOG_FILE"; then
    print_success "Strings extracted from APK"
    

    grep -E "https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" "$SESSION_DIR/static/strings.txt" > "$SESSION_DIR/network/urls.txt" 2>/dev/null || true
    print_status "Extracted $(wc -l < "$SESSION_DIR/network/urls.txt" 2>/dev/null || echo "0") URLs"
else
    print_warning "Failed to extract strings from APK"
fi


show_progress "Extracting certificate information"
if [[ -f "$APK_PATH" ]]; then
    if unzip -l "$APK_PATH" | grep -q "META-INF/.*\.RSA"; then

        CERT_FILE=$(unzip -l "$APK_PATH" | grep "META-INF/.*\.RSA" | head -1 | awk '{print $4}')
        mkdir -p "$SESSION_DIR/static/cert"
        if unzip -p "$APK_PATH" "$CERT_FILE" > "$SESSION_DIR/static/cert/certificate.rsa" 2>/dev/null; then

            if command -v keytool &>/dev/null; then
                keytool -printcert -file "$SESSION_DIR/static/cert/certificate.rsa" > "$SESSION_DIR/static/cert_info.txt" 2>/dev/null || true
                print_success "Certificate information extracted"
            else
                print_warning "keytool not found, certificate saved but not analyzed"
            fi
        else
            print_warning "Failed to extract certificate from APK"
        fi
    else
        print_warning "No certificate found in APK"
    fi
fi


if [[ -f "tools/scripts/enhanced_data_extractor.py" ]]; then
    run_cmd "python3 tools/scripts/enhanced_data_extractor.py '$APK_PATH' '$PACKAGE_NAME'" "Enhanced Data Extraction" "$SESSION_DIR/logs/data_extractor.log"
    

    EXTRACTOR_DIR=$(find . -maxdepth 1 -name "comprehensive_analysis_$(date +%Y%m%d)*" -type d | head -1)
    if [[ -d "$EXTRACTOR_DIR" ]]; then
        cp -r "$EXTRACTOR_DIR"/* "$SESSION_DIR/" 2>/dev/null || true
        rm -rf "$EXTRACTOR_DIR"
        print_success "Data extractor results moved to session directory"
    fi
fi


if [[ "$ENABLE_NETWORK" == "true" ]]; then
    if [[ -f "tools/python/network_analyzer.py" ]]; then
        run_cmd "python3 tools/python/network_analyzer.py '$SESSION_DIR/network/urls.txt'" "Network Analysis" "$SESSION_DIR/network/network_analysis.json"
    elif [[ -f "tools/scripts/domain_osint.sh" ]]; then

        TOP_DOMAIN=$(head -1 "$SESSION_DIR/network/urls.txt" 2>/dev/null | grep -o 'https\?://[^/]*' | sed 's,https\?://,,')
        if [[ -n "$TOP_DOMAIN" ]]; then
            run_cmd "tools/scripts/domain_osint.sh '$TOP_DOMAIN'" "Domain OSINT" "$SESSION_DIR/network/domain_osint.txt"
        else
            print_warning "No domains found for OSINT analysis"
        fi
    else
        print_warning "Network analyzer not found, skipping network analysis"
    fi
fi


show_progress "Generating consolidated report"


STATIC_FILES=$(find "$SESSION_DIR/static" -type f | wc -l)
NETWORK_FILES=$(find "$SESSION_DIR/network" -type f | wc -l)
DYNAMIC_FILES=$(find "$SESSION_DIR/dynamic" -type f | wc -l)


STATIC_STATUS=$([ "$STATIC_FILES" -gt 0 ] && echo "✓ Completed" || echo "✗ Failed")
NETWORK_STATUS=$([ "$NETWORK_FILES" -gt 0 ] && echo "✓ Completed" || echo "✗ Skipped")
DYNAMIC_STATUS=$([ "$DYNAMIC_FILES" -gt 0 ] && echo "✓ Completed" || echo "✗ Skipped")


cat > "$SESSION_DIR/analysis_summary.txt" << EOL
APK Analysis Summary
===================
Timestamp: $TIMESTAMP
APK: $APK_PATH
Package: $PACKAGE_NAME
Session: $SESSION_DIR

Analysis Components:
- Static Analysis: $STATIC_STATUS ($STATIC_FILES files)
- Network Analysis: $NETWORK_STATUS ($NETWORK_FILES files)
- Dynamic Analysis: $DYNAMIC_STATUS ($DYNAMIC_FILES files)

Artifacts Location:
- Extracted Resources: $SESSION_DIR/extracted/
- Static Analysis: $SESSION_DIR/static/
- Network Analysis: $SESSION_DIR/network/
- Dynamic Analysis: $SESSION_DIR/dynamic/
- Logs: $SESSION_DIR/logs/

Key Findings:
$(grep -E "certificate|permission|danger|suspicious|warning" "$SESSION_DIR/static/"*.txt 2>/dev/null | head -5 | sed 's/^/- /' || echo "- No significant findings automatically detected")

Extracted URLs: $(wc -l < "$SESSION_DIR/network/urls.txt" 2>/dev/null || echo "0")
Total Files Generated: $(find "$SESSION_DIR" -type f | wc -l)

For complete results, review the files in the session directory.
EOL


ln -sf "$SESSION_DIR" "analysis_results/sessions/latest"

print_success "Analysis session completed: $SESSION_DIR"
echo -e "${GREEN}📊 View summary: cat $SESSION_DIR/analysis_summary.txt${NC}"
echo -e "${GREEN}📁 Quick access: analysis_results/sessions/latest${NC}"


TOTAL_FILES=$(find "$SESSION_DIR" -type f | wc -l)
SESSION_SIZE=$(du -sh "$SESSION_DIR" | cut -f1)

echo -e "\n${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC} ${BOLD}Analysis Complete${NC}                                           ${CYAN}║${NC}"
echo -e "${CYAN}║${NC} Files generated: $TOTAL_FILES                                   ${CYAN}║${NC}"
echo -e "${CYAN}║${NC} Session size: $SESSION_SIZE                                       ${CYAN}║${NC}"
echo -e "${CYAN}║${NC} Completed: $(date '+%Y-%m-%d %H:%M:%S')                           ${CYAN}║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
