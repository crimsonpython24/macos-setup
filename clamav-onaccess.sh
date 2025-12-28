#!/usr/bin/env bash
set -euo pipefail

# Configuration
WATCH_DIRS=(
  "$HOME"
)
LOG_FILE="$HOME/clamav-logs/onaccess-$(date +%F).log"
CLAMD_SOCKET="/opt/local/var/run/clamav/clamd.socket"
EMAIL="yjwarrenwang@gmail.com"  # Change this; ignored if email not configured
SCAN_TYPE="On-Access"

# Rate limiting: minimum seconds between notifications
RATE_LIMIT_SECONDS=60
LAST_ALERT_FILE="/tmp/clamav-onaccess-last-alert"

# Create log directory
mkdir -p "$(dirname "$LOG_FILE")"

# Function to check rate limiting
should_alert() {
  local now
  now=$(date +%s)
  
  if [[ -f "$LAST_ALERT_FILE" ]]; then
    local last_time
    last_time=$(cat "$LAST_ALERT_FILE" 2>/dev/null || echo "0")
    local diff=$((now - last_time))
    if [[ $diff -lt $RATE_LIMIT_SECONDS ]]; then
      return 1
    fi
  fi
  
  echo "$now" > "$LAST_ALERT_FILE"
  return 0
}

# Function to scan a file
scan_file() {
  local file="$1"
  
  [[ -f "$file" ]] || return 0
  
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Scanning: $file" >> "$LOG_FILE"
  
  if [[ -S "$CLAMD_SOCKET" ]]; then
    local scan_result
    scan_result=$(/opt/local/bin/clamdscan --no-summary "$file" 2>&1 || true)
    
    if echo "$scan_result" | grep -qi "FOUND"; then
      local virus_name
      virus_name=$(echo "$scan_result" | grep -i "FOUND" | awk '{print $2}')
      
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFECTED: $file" >> "$LOG_FILE"
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] Virus: $virus_name" >> "$LOG_FILE"
      
      local file_dir file_name
      file_dir=$(dirname "$file")
      file_name=$(basename "$file")
      
      if ! should_alert "$file"; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Rate limited - skipping alert" >> "$LOG_FILE"
        return 0
      fi
      
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] Sending alerts..." >> "$LOG_FILE"
      
      # All alerts fire in parallel (non-blocking)
      {
        echo "ClamAV ${SCAN_TYPE} Alert
==============================

A virus was detected in real-time on your Mac.

File: $file
Virus: $virus_name
Time: $(date)

ACTION REQUIRED: Delete this file immediately.

---
ClamAV ${SCAN_TYPE} Scanning" | mail -s "URGENT: ClamAV ${SCAN_TYPE} - Virus Detected!" "$EMAIL" 2>/dev/null
      } &
      
      osascript -e "display notification \"VIRUS FOUND: $file_name - Delete immediately!\" with title \"ClamAV ${SCAN_TYPE} Alert\" sound name \"Basso\"" 2>/dev/null &
      
      {
        BUTTON_RESULT=$(osascript -e "display dialog \"ClamAV ${SCAN_TYPE} Alert

A virus was detected in real-time!

File: $file_name
Virus: $virus_name
Location: $file_dir

Delete this file immediately.\" buttons {\"Open Folder\", \"OK\"} default button 1 with title \"ClamAV ${SCAN_TYPE} Alert\" with icon caution giving up after 300" -e "button returned of result" 2>/dev/null || echo "OK")
        
        [[ "$BUTTON_RESULT" == "Open Folder" ]] && open "$file_dir"
      } &
      
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] Alerts spawned" >> "$LOG_FILE"
    else
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] Clean" >> "$LOG_FILE"
    fi
  else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: clamd not running" >> "$LOG_FILE"
  fi
}

echo "[$(date '+%Y-%m-%d %H:%M:%S')] ClamAV ${SCAN_TYPE} Scanner Started" >> "$LOG_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Monitoring: ${WATCH_DIRS[*]}" >> "$LOG_FILE"

/opt/local/bin/fswatch -0 -r \
  -e "\.git" \
  -e "node_modules" \
  -e "\.Trash" \
  -e "\.DS_Store" \
  -e "Library/Caches" \
  -e "Library/Logs" \
  -e "Library/Application Support/Google" \
  -e "Library/Application Support/Slack" \
  -e "\.viminfo" \
  "${WATCH_DIRS[@]}" | \
  while IFS= read -r -d '' file; do
    scan_file "$file"
  done
