#!/usr/bin/env zsh



set -euo pipefail


BOLD="\033[1m"
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
CYAN="\033[36m"
RESET="\033[0m"


OUTPUT_JSON=false
QUIET_MODE=false
MAX_RESULTS=20
TIMEOUT=15
DOMAINS=()


while [[ $# -gt 0 ]]; do
  case "$1" in
    --json)
      OUTPUT_JSON=true
      shift
      ;;
    --quiet|-q)
      QUIET_MODE=true
      shift
      ;;
    --max=*)
      MAX_RESULTS="${1#*=}"
      shift
      ;;
    --timeout=*)
      TIMEOUT="${1#*=}"
      shift
      ;;
    -*)
      echo "${RED}Error: Unknown option $1${RESET}" >&2
      echo "Usage: $0 [--json] [--quiet] [--max=N] [--timeout=N] domain1 domain2..." >&2
      exit 1
      ;;
    *)
      DOMAINS+=("$1")
      shift
      ;;
  esac
done

if [[ ${#DOMAINS[@]} -eq 0 ]]; then
  echo "${RED}Error: No domains specified${RESET}" >&2
  echo "Usage: $0 [--json] [--quiet] [--max=N] [--timeout=N] domain1 domain2..." >&2
  exit 1
fi


log_info() {
  [[ "$QUIET_MODE" == "true" ]] || echo -e "${BLUE}[INFO]${RESET} $1"
}

log_success() {
  [[ "$QUIET_MODE" == "true" ]] || echo -e "${GREEN}[SUCCESS]${RESET} $1"
}

log_warning() {
  [[ "$QUIET_MODE" == "true" ]] || echo -e "${YELLOW}[WARNING]${RESET} $1" >&2
}

log_error() {
  [[ "$QUIET_MODE" == "true" ]] || echo -e "${RED}[ERROR]${RESET} $1" >&2
}

check_command() {
  if ! command -v "$1" &>/dev/null; then
    log_warning "$1 command not found, some functionality will be limited"
    return 1
  fi
  return 0
}


check_command curl
check_command dig || check_command host || check_command nslookup


if [[ "$OUTPUT_JSON" == "true" ]]; then
  echo '{'
  echo '  "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",'
  echo '  "domains": ['
fi


for ((i=0; i<${#DOMAINS[@]}; i++)); do
  d="${DOMAINS[$i]}"
  
  if [[ "$OUTPUT_JSON" == "true" ]]; then

    echo '    {'
    echo '      "domain": "'$d'",'
    

    echo '      "dns": {'
    

    echo -n '        "a_records": ['
    if check_command dig &>/dev/null; then
      A_RECORDS=($(dig +short A "$d" 2>/dev/null || echo ""))
      for ((j=0; j<${#A_RECORDS[@]}; j++)); do
        echo -n '"'${A_RECORDS[$j]}'"'
        [[ $j -lt $((${#A_RECORDS[@]}-1)) ]] && echo -n ', '
      done
    elif check_command host &>/dev/null; then
      A_RECORDS=($(host "$d" | grep "has address" | awk '{print $4}' || echo ""))
      for ((j=0; j<${#A_RECORDS[@]}; j++)); do
        echo -n '"'${A_RECORDS[$j]}'"'
        [[ $j -lt $((${#A_RECORDS[@]}-1)) ]] && echo -n ', '
      done
    fi
    echo '],'
    

    echo -n '        "ns_records": ['
    if check_command dig &>/dev/null; then
      NS_RECORDS=($(dig +short NS "$d" 2>/dev/null || echo ""))
      for ((j=0; j<${#NS_RECORDS[@]}; j++)); do
        echo -n '"'${NS_RECORDS[$j]}'"'
        [[ $j -lt $((${#NS_RECORDS[@]}-1)) ]] && echo -n ', '
      done
    elif check_command host &>/dev/null; then
      NS_RECORDS=($(host -t NS "$d" | grep "name server" | awk '{print $4}' || echo ""))
      for ((j=0; j<${#NS_RECORDS[@]}; j++)); do
        echo -n '"'${NS_RECORDS[$j]}'"'
        [[ $j -lt $((${#NS_RECORDS[@]}-1)) ]] && echo -n ', '
      done
    fi
    echo '],'
    

    echo -n '        "mx_records": ['
    if check_command dig &>/dev/null; then
      MX_RECORDS=($(dig +short MX "$d" 2>/dev/null || echo ""))
      for ((j=0; j<${#MX_RECORDS[@]}; j++)); do
        echo -n '"'${MX_RECORDS[$j]}'"'
        [[ $j -lt $((${#MX_RECORDS[@]}-1)) ]] && echo -n ', '
      done
    elif check_command host &>/dev/null; then
      MX_RECORDS=($(host -t MX "$d" | grep "mail is handled" | awk '{print $NF}' || echo ""))
      for ((j=0; j<${#MX_RECORDS[@]}; j++)); do
        echo -n '"'${MX_RECORDS[$j]}'"'
        [[ $j -lt $((${#MX_RECORDS[@]}-1)) ]] && echo -n ', '
      done
    fi
    echo '],'
    

    echo -n '        "txt_records": ['
    if check_command dig &>/dev/null; then
      TXT_RECORDS=($(dig +short TXT "$d" 2>/dev/null | tr -d '\n' || echo ""))
      for ((j=0; j<${#TXT_RECORDS[@]}; j++)); do
        echo -n '"'${TXT_RECORDS[$j]}'"'
        [[ $j -lt $((${#TXT_RECORDS[@]}-1)) ]] && echo -n ', '
      done
    elif check_command host &>/dev/null; then
      TXT_RECORDS=($(host -t TXT "$d" | grep "descriptive text" | awk -F'"' '{print $2}' || echo ""))
      for ((j=0; j<${#TXT_RECORDS[@]}; j++)); do
        echo -n '"'${TXT_RECORDS[$j]}'"'
        [[ $j -lt $((${#TXT_RECORDS[@]}-1)) ]] && echo -n ', '
      done
    fi
    echo ']'
    
    echo '      },'
    

    echo '      "http": {'
    if check_command curl &>/dev/null; then

      HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -m "$TIMEOUT" "http://$d" 2>/dev/null || echo "0")
      echo '        "http_status": '$HTTP_STATUS','
      

      HTTPS_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -m "$TIMEOUT" "https://$d" 2>/dev/null || echo "0")
      echo '        "https_status": '$HTTPS_STATUS','
      

      HEADERS=$(curl -sI -m "$TIMEOUT" "https://$d" 2>/dev/null || echo "")
      echo '        "security_headers": {'
      echo '          "hsts": '$(echo "$HEADERS" | grep -i "strict-transport-security" >/dev/null && echo "true" || echo "false")','
      echo '          "csp": '$(echo "$HEADERS" | grep -i "content-security-policy" >/dev/null && echo "true" || echo "false")','
      echo '          "xfo": '$(echo "$HEADERS" | grep -i "x-frame-options" >/dev/null && echo "true" || echo "false")','
      echo '          "xxp": '$(echo "$HEADERS" | grep -i "x-xss-protection" >/dev/null && echo "true" || echo "false")
      echo '        }'
    else
      echo '        "http_status": 0,'
      echo '        "https_status": 0,'
      echo '        "security_headers": {'
      echo '          "hsts": false,'
      echo '          "csp": false,'
      echo '          "xfo": false,'
      echo '          "xxp": false'
      echo '        }'
    fi
    echo '      },'
    

    echo '      "certificate_transparency": {'
    if check_command curl &>/dev/null; then
      echo '        "found": true,'
      echo '        "subdomains": ['
      

      CT_DATA=$(curl -s "https://crt.sh/?q=%25.$d&output=json" 2>/dev/null || echo "[]")
      

      if check_command jq &>/dev/null; then
        SUBDOMAINS=$(echo "$CT_DATA" | jq -r '.[].name_value' 2>/dev/null | sort -u | head -n "$MAX_RESULTS" || echo "")
      else
        SUBDOMAINS=$(echo "$CT_DATA" | grep -oE '"name_value":"[^"]+"' 2>/dev/null | cut -d'"' -f4 | sort -u | head -n "$MAX_RESULTS" || echo "")
      fi
      

      SUBDOMAIN_ARRAY=($SUBDOMAINS)
      for ((j=0; j<${#SUBDOMAIN_ARRAY[@]}; j++)); do
        echo -n '          "'${SUBDOMAIN_ARRAY[$j]}'"'
        [[ $j -lt $((${#SUBDOMAIN_ARRAY[@]}-1)) ]] && echo ',' || echo ''
      done
      
      echo '        ]'
    else
      echo '        "found": false,'
      echo '        "subdomains": []'
    fi
    echo '      },'
    

    echo '      "geo_ip": {'
    if check_command curl &>/dev/null && [[ ${#A_RECORDS[@]} -gt 0 ]]; then
      FIRST_IP="${A_RECORDS[0]}"
      GEO_DATA=$(curl -s "https://ipinfo.io/$FIRST_IP/json" -m "$TIMEOUT" 2>/dev/null || echo '{"ip":"'$FIRST_IP'","error":"Failed to fetch geo data"}')
      
      if check_command jq &>/dev/null; then

        echo "$GEO_DATA" | jq '.' | grep -v "^{$\|^}$" | sed 's/^/        /'
      else

        echo "$GEO_DATA" | sed 's/{//' | sed 's/}//' | sed 's/,$//' | sed 's/^/        /'
      fi
    else
      echo '        "error": "No IP addresses found or curl unavailable"'
    fi
    echo '      }'
    

    if [[ $i -lt $((${#DOMAINS[@]}-1)) ]]; then
      echo '    },'
    else
      echo '    }'
    fi
  else

    echo -e "\n${CYAN}=== COMPREHENSIVE ANALYSIS FOR $d ===${RESET}"
    
    echo -e "${BOLD}-- WHOIS Information --${RESET}"
    if check_command whois &>/dev/null; then
      whois "$d" | head -n 20 || echo "whois lookup failed"
    else
      echo "whois command not available"
    fi
    
    echo -e "\n${BOLD}-- DNS Records Analysis --${RESET}"
    if check_command dig &>/dev/null; then
      echo "NS Records:"
      dig +short NS "$d" || echo "NS lookup failed"
      echo "A Records:"
      dig +short A "$d" || echo "A lookup failed"
      echo "AAAA Records:"
      dig +short AAAA "$d" || echo "AAAA lookup failed"
      echo "MX Records:"
      dig +short MX "$d" || echo "MX lookup failed"
      echo "TXT Records:"
      dig +short TXT "$d" || echo "TXT lookup failed"
    elif check_command host &>/dev/null; then
      echo "DNS Records:"
      host -a "$d" || echo "DNS lookup failed"
    else
      echo "No DNS lookup tools available"
    fi
    
    echo -e "\n${BOLD}-- SSL/TLS Certificate Transparency --${RESET}"
    if check_command curl &>/dev/null; then
      echo "Subdomains from Certificate Transparency:"
      curl -s "https://crt.sh/?q=%25.$d&output=json" 2>/dev/null | 
        grep -oE '"name_value":"[^"]+"' | cut -d'"' -f4 | sort -u | head -n "$MAX_RESULTS" || 
        echo "Failed to retrieve certificate transparency data"
    else
      echo "curl not available for certificate transparency checks"
    fi
    
    echo -e "\n${BOLD}-- HTTP/HTTPS Response Analysis --${RESET}"
    if check_command curl &>/dev/null; then
      echo "HTTP Response:"
      curl -sI -m "$TIMEOUT" "http://$d" 2>/dev/null | head -10 || echo "HTTP connection failed"
      
      echo -e "\nHTTPS Response:"
      curl -sI -m "$TIMEOUT" "https://$d" 2>/dev/null | head -10 || echo "HTTPS connection failed"
      
      echo -e "\nSecurity Headers:"
      HEADERS=$(curl -sI -m "$TIMEOUT" "https://$d" 2>/dev/null)
      echo "$HEADERS" | grep -i "strict-transport-security" || echo "HSTS: Not found"
      echo "$HEADERS" | grep -i "content-security-policy" || echo "CSP: Not found"
      echo "$HEADERS" | grep -i "x-frame-options" || echo "X-Frame-Options: Not found"
      echo "$HEADERS" | grep -i "x-xss-protection" || echo "X-XSS-Protection: Not found"
    else
      echo "curl not available for HTTP/HTTPS analysis"
    fi
    
    echo -e "\n${BOLD}-- GeoIP Information --${RESET}"
    if check_command dig &>/dev/null && check_command curl &>/dev/null; then
      IP=$(dig +short A "$d" 2>/dev/null | head -1)
      if [[ -n "$IP" ]]; then
        echo "IP: $IP"
        curl -s "https://ipinfo.io/$IP/json" -m "$TIMEOUT" 2>/dev/null || echo "GeoIP lookup failed"
      else
        echo "No IP addresses found"
      fi
    elif check_command host &>/dev/null && check_command curl &>/dev/null; then
      IP=$(host "$d" 2>/dev/null | grep "has address" | head -1 | awk '{print $4}')
      if [[ -n "$IP" ]]; then
        echo "IP: $IP"
        curl -s "https://ipinfo.io/$IP/json" -m "$TIMEOUT" 2>/dev/null || echo "GeoIP lookup failed"
      else
        echo "No IP addresses found"
      fi
    else
      echo "Required tools not available for GeoIP lookup"
    fi
    
    echo -e "\n${BOLD}-- Modern Threat Intelligence --${RESET}"
    echo "Check these resources for threat intelligence:"
    echo "• VirusTotal: https://www.virustotal.com/gui/domain/$d"
    echo "• SecurityTrails: https://securitytrails.com/domain/$d"
    echo "• Shodan: https://www.shodan.io/search?query=$d"
    echo "• URLScan: https://urlscan.io/search/#$d"
    echo "• DNSDB: https://www.farsightsecurity.com/tools/dnsdb-scout/"
    
    log_success "Analysis for $d completed"
  fi
done


if [[ "$OUTPUT_JSON" == "true" ]]; then
  echo '  ],'
  echo '  "generated_by": "Enhanced Domain OSINT Tool",'
  echo '  "version": "2.0"'
  echo '}'
else
  echo -e "\n${CYAN}=== ANALYSIS COMPLETE ===${RESET}"
  echo "# Report generated on $(date)"
fi

log_info "Analysis of ${#DOMAINS[@]} domain(s) completed"
