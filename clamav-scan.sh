#!/usr/bin/env bash
set -euo pipefail

# Configuration
LOG_DIR="/var/root/clamav-logs"
QUARANTINE_DIR="/var/root/quarantine"
EMAIL="yjwarrenwang@gmail.com"  # Change this to your email
SCAN_TYPE="Daily Scan"

# Create directories
mkdir -p "$LOG_DIR" "$QUARANTINE_DIR"

# If no arguments, default to home directory
TARGETS=("${@:-$HOME}")

# Log file for this scan
SCAN_LOG="$LOG_DIR/scan-$(date +%F).log"

# Temporary file for scan results
SCAN_RESULT_FILE=$(mktemp)

# Auto-detect clamscan location
CLAMSCAN=""
for p in \
  /opt/local/bin/clamscan \
  /usr/local/bin/clamscan \
  /opt/homebrew/bin/clamscan
do
  if [[ -x "$p" ]]; then
    CLAMSCAN="$p"
    break
  fi
done

if [[ -z "$CLAMSCAN" ]]; then
  echo "[!] clamscan not found. Please check your installation path." >&2
  exit 2
fi

echo "============================================" | tee -a "$SCAN_LOG"
echo "ClamAV ${SCAN_TYPE} - $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$SCAN_LOG"
echo "Using: $CLAMSCAN (standalone mode - full statistics)" | tee -a "$SCAN_LOG"
echo "Targets: ${TARGETS[*]}" | tee -a "$SCAN_LOG"
echo "============================================" | tee -a "$SCAN_LOG"
echo "" | tee -a "$SCAN_LOG"

# Run clamscan with full output
for TARGET in "${TARGETS[@]}"; do
  echo "Scanning: $TARGET" | tee -a "$SCAN_LOG"
  
  "$CLAMSCAN" -r -i \
    --move="$QUARANTINE_DIR" \
    --exclude="\.viminfo$" \
    --exclude="\.bnnsir$" \
    --exclude="\.com\.apple\.containermanagerd\.metadata\.plist$" \
    --exclude="com\.apple\.AddressBook\.plist$" \
    --exclude="com\.apple\.homed.*\.plist$" \
    --exclude="com\.apple\.MobileSMS\.plist$" \
    --exclude-dir="\.git" \
    --exclude-dir="node_modules" \
    --exclude-dir="Library/Caches" \
    --exclude-dir="\.Trash" \
    --exclude-dir="Library/Application Support/Knowledge" \
    --exclude-dir="Library/Application Support/com.apple.TCC" \
    --exclude-dir="Library/Application Support/AddressBook" \
    --exclude-dir="Library/Application Support/FaceTime" \
    --exclude-dir="Library/Application Support/CallHistoryDB" \
    --exclude-dir="Library/Autosave Information" \
    --exclude-dir="Library/Group Containers" \
    --exclude-dir="Library/Daemon Containers" \
    --exclude-dir="Library/Biome" \
    "$TARGET" 2>&1 | tee -a "$SCAN_LOG" | tee -a "$SCAN_RESULT_FILE" || true
done

echo "" | tee -a "$SCAN_LOG"

# Parse infected count - strip whitespace and validate
INFECTED_COUNT=$(grep -i "Infected files:" "$SCAN_RESULT_FILE" 2>/dev/null | awk '{sum += $3} END {print sum}' || echo "0")
INFECTED_COUNT="${INFECTED_COUNT:-0}"
if ! [[ "$INFECTED_COUNT" =~ ^[0-9]+$ ]]; then
  INFECTED_COUNT=0
fi

if [[ "$INFECTED_COUNT" -gt 0 ]]; then
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] ALERT: $INFECTED_COUNT infected file(s) found!" | tee -a "$SCAN_LOG"
  
  # Send email (fails silently if email not configured)
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Sending email alert..." | tee -a "$SCAN_LOG"
  {
    echo "ClamAV ${SCAN_TYPE} Alert"
    echo "========================"
    echo ""
    echo "INFECTED FILES FOUND: $INFECTED_COUNT"
    echo ""
    echo "Infected files have been moved to: $QUARANTINE_DIR"
    echo ""
    echo "--- Full Scan Results ---"
    cat "$SCAN_RESULT_FILE"
  } | mail -s "URGENT: ClamAV ${SCAN_TYPE} - $INFECTED_COUNT Infected File(s) Found!" "$EMAIL" 2>/dev/null || true
  
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Email queued" | tee -a "$SCAN_LOG"
  
  # Show notifications in background (non-blocking)
  (
    osascript -e 'tell application "System Events" to display notification "'"$INFECTED_COUNT"' infected file(s) found and quarantined!" with title "ClamAV '"${SCAN_TYPE}"' Alert" sound name "Basso"' 2>/dev/null || true
    
    osascript <<EOF
tell application "System Events"
  activate
  display dialog "ClamAV ${SCAN_TYPE} Alert

$INFECTED_COUNT infected file(s) detected and moved to quarantine!

Location: $QUARANTINE_DIR

To view quarantine, run in Terminal:
sudo ls $QUARANTINE_DIR

Please review and delete immediately." buttons {"OK"} default button 1 with title "ClamAV ${SCAN_TYPE} Alert" with icon caution giving up after 300
end tell
EOF
  ) 2>/dev/null &
  
  disown
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Alerts sent" | tee -a "$SCAN_LOG"
else
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Scan complete - No infections found" | tee -a "$SCAN_LOG"
fi

# Cleanup
rm -f "$SCAN_RESULT_FILE"
