#!/usr/bin/env bash
set -euo pipefail

# Configuration - root-owned directories for security
LOG_DIR="/var/root/clamav-logs"
QUARANTINE_DIR="/var/root/quarantine"
EMAIL="yjwarrenwang@gmail.com"
SCAN_TYPE="Daily Scan"

# Hardcoded scan target for user warren
SCAN_TARGET="/Users/warren"

# Create directories
mkdir -p "$LOG_DIR" "$QUARANTINE_DIR"

# Log file for this scan
SCAN_LOG="$LOG_DIR/scan-$(date +%F).log"

# Temporary file for scan results
SCAN_RESULT_FILE=$(mktemp)

# Cleanup function
cleanup() {
    rm -f "$SCAN_RESULT_FILE"
}
trap cleanup EXIT

# Use the FDA-wrapped clamscan
CLAMSCAN="/Applications/ClamScan.app/Contents/MacOS/ClamScan"

if [[ ! -x "$CLAMSCAN" ]]; then
  echo "[!] ClamScan.app wrapper not found at $CLAMSCAN" >&2
  echo "[!] Please ensure the wrapper is created and has FDA access." >&2
  exit 2
fi

# Check if virus database exists
DB_DIR="/opt/local/share/clamav"
if [[ ! -f "$DB_DIR/main.cvd" ]] && [[ ! -f "$DB_DIR/main.cld" ]]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Virus database not found in $DB_DIR" | tee -a "$SCAN_LOG"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Run: sudo freshclam" | tee -a "$SCAN_LOG"
    exit 1
fi

echo "============================================" | tee -a "$SCAN_LOG"
echo "ClamAV ${SCAN_TYPE} - $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$SCAN_LOG"
echo "Using: $CLAMSCAN (standalone mode - full statistics)" | tee -a "$SCAN_LOG"
echo "Target: $SCAN_TARGET" | tee -a "$SCAN_LOG"
echo "============================================" | tee -a "$SCAN_LOG"
echo "" | tee -a "$SCAN_LOG"

# Run clamscan with full output
echo "Scanning: $SCAN_TARGET" | tee -a "$SCAN_LOG"

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
  --exclude-dir="quarantine" \
  --exclude-dir="/var/root/quarantine" \
  "$SCAN_TARGET" 2>&1 | tee -a "$SCAN_LOG" | tee -a "$SCAN_RESULT_FILE" || true

echo "" | tee -a "$SCAN_LOG"

# Parse infected count
INFECTED_COUNT=$(grep -i "Infected files:" "$SCAN_RESULT_FILE" 2>/dev/null | awk '{sum += $3} END {print sum}' || echo "0")
INFECTED_COUNT="${INFECTED_COUNT:-0}"
if ! [[ "$INFECTED_COUNT" =~ ^[0-9]+$ ]]; then
  INFECTED_COUNT=0
fi

if [[ "$INFECTED_COUNT" -gt 0 ]]; then
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] ALERT: $INFECTED_COUNT infected file(s) found!" | tee -a "$SCAN_LOG"
  
  # Send email (fails silently if email not configured)
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Sending email alert..." | tee -a "$SCAN_LOG"
  if {
    echo "ClamAV ${SCAN_TYPE} Alert"
    echo "========================"
    echo ""
    echo "INFECTED FILES FOUND: $INFECTED_COUNT"
    echo ""
    echo "Infected files have been moved to: $QUARANTINE_DIR"
    echo ""
    echo "To view and clean up quarantine, run:"
    echo "  sudo ls $QUARANTINE_DIR"
    echo "  sudo rm -rf $QUARANTINE_DIR/*"
    echo ""
    echo "--- Full Scan Results ---"
    cat "$SCAN_RESULT_FILE"
  } | mail -s "URGENT: ClamAV ${SCAN_TYPE} - $INFECTED_COUNT Infected File(s) Found!" "$EMAIL" 2>/dev/null; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Email sent successfully" | tee -a "$SCAN_LOG"
  else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Email sending failed (postfix may not be configured)" | tee -a "$SCAN_LOG"
  fi
  
  # Show notifications - these run in foreground but with timeouts
  # Note: AbandonProcessGroup in the plist allows these to complete even after script exits
  (
    # Notification
    osascript -e 'tell application "System Events" to display notification "'"$INFECTED_COUNT"' infected file(s) found and quarantined!" with title "ClamAV '"${SCAN_TYPE}"' Alert" sound name "Basso"' 2>/dev/null || true
    
    # Dialog
    osascript <<EOF 2>/dev/null || true
tell application "System Events"
  activate
  display dialog "ClamAV ${SCAN_TYPE} Alert

$INFECTED_COUNT infected file(s) detected and moved to quarantine!

Quarantine location: $QUARANTINE_DIR

To view quarantine:
  sudo ls $QUARANTINE_DIR

To clean up quarantine:
  sudo rm -rf $QUARANTINE_DIR/*

Please review and delete immediately." buttons {"OK"} default button 1 with title "ClamAV ${SCAN_TYPE} Alert" with icon caution giving up after 300
end tell
EOF
  ) &
  
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Alerts spawned" | tee -a "$SCAN_LOG"
else
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Scan complete - No infections found" | tee -a "$SCAN_LOG"
fi

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Daily scan finished" | tee -a "$SCAN_LOG"
