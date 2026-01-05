#!/usr/bin/env bash
set -euo pipefail

# Configuration
LOG_FILE="$HOME/clamav-logs/onaccess-$(date +%F).log"
QUARANTINE_DIR="$HOME/quarantine"
CLAMD_SOCKET="/opt/local/var/run/clamav/clamd.socket"
EMAIL="yjwarrenwang@gmail.com"
SCAN_TYPE="On-Access"

# Create directories
mkdir -p "$(dirname "$LOG_FILE")" "$QUARANTINE_DIR"

# ============================================================================
# Watch Paths Configuration
# ============================================================================
WATCH_PATHS=(
    # User directories
    "$HOME/Downloads"
    "$HOME/Desktop"
    "$HOME/Documents"
    
    # Temporary directories
    "/tmp"
    "/private/tmp"
    "${TMPDIR:-/tmp}"
    
    # Browser data (downloads, cache, extensions)
    "$HOME/Library/Application Support/Google/Chrome"
    "$HOME/Library/Application Support/Firefox"
    "$HOME/Library/Application Support/Microsoft Edge"
    "$HOME/Library/Application Support/BraveSoftware"
    "$HOME/Library/Containers/com.apple.Safari"
    "$HOME/Library/Safari"
    
    # Package managers and dev tools
    "/opt/local/var/macports/distfiles"
    "$HOME/.cargo/registry"
    "$HOME/.npm/_cacache"
    "$HOME/go/pkg/mod"
    
    # Mail attachments
    "$HOME/Library/Containers/com.apple.mail/Data/Library/Mail Downloads"
    "$HOME/Library/Mail/V*/*/Attachments"
    
    # Messaging apps
    "$HOME/Library/Application Support/Telegram Desktop"
    "$HOME/Library/Group Containers/"*".com.apple.iChat"
    "$HOME/Library/Application Support/Signal"
    "$HOME/Library/Application Support/Discord"
    "$HOME/Library/Application Support/Slack"
    
    # Archive extraction locations
    "$HOME/Library/Application Support/The Unarchiver"
)

# Exclusion patterns (high-churn or system-managed)
EXCLUDE_PATTERNS=(
    "\.git"
    "node_modules"
    "\.Trash"
    "\.DS_Store"
    "\.localized"
    "\.viminfo"
    "\.swp$"
    "\.swo$"
    "Library/Caches"
    "Library/Logs"
    "Library/Saved Application State"
    "Library/WebKit"
    "CacheStorage"
    "Cache"
    "GPUCache"
    "ShaderCache"
    "Code Cache"
    "ScriptCache"
    "IndexedDB"
    "Local Storage"
    "Session Storage"
    "Cookies"
    "databases"
    "\.journal$"
    "\.sqlite-wal$"
    "\.sqlite-shm$"
    "lock$"
    "\.lock$"
    "LOCK$"
)

# Build fswatch exclude arguments
FSWATCH_EXCLUDES=()
for pattern in "${EXCLUDE_PATTERNS[@]}"; do
    FSWATCH_EXCLUDES+=(-e "$pattern")
done

# Filter to only existing paths (handles glob expansion)
EXISTING_PATHS=()
for p in "${WATCH_PATHS[@]}"; do
    # Handle glob patterns
    for expanded in $p; do
        [[ -e "$expanded" ]] && EXISTING_PATHS+=("$expanded")
    done
done

# Deduplicate paths
EXISTING_PATHS=($(printf '%s\n' "${EXISTING_PATHS[@]}" | sort -u))

# ============================================================================
# Functions
# ============================================================================

# Skip certain file types that are unlikely to be malware and cause noise
should_skip_file() {
    local file="$1"
    local basename
    basename=$(basename "$file")
    
    # Skip lock files, journals, temp files
    case "$basename" in
        *.lock|*.LOCK|lock|LOCK|*.journal|*.sqlite-wal|*.sqlite-shm)
            return 0
            ;;
        .DS_Store|.localized|*.swp|*.swo|*~)
            return 0
            ;;
    esac
    
    # Skip if path contains cache/log directories
    case "$file" in
        */Caches/*|*/Cache/*|*/Logs/*|*/GPUCache/*|*/ShaderCache/*)
            return 0
            ;;
        */IndexedDB/*|*/Local\ Storage/*|*/Session\ Storage/*)
            return 0
            ;;
    esac
    
    return 1
}

scan_file() {
    local file="$1"
    
    # Skip non-files
    [[ -f "$file" ]] || return 0
    
    # Skip files we shouldn't scan
    should_skip_file "$file" && return 0
    
    # Skip very small files (< 50 bytes) - unlikely to be malware
    local size
    size=$(stat -f%z "$file" 2>/dev/null || echo "0")
    [[ "$size" -lt 50 ]] && return 0
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Scanning: $file" >> "$LOG_FILE"
    
    if [[ -S "$CLAMD_SOCKET" ]]; then
        local scan_result
        scan_result=$(/opt/local/bin/clamdscan --no-summary --move="$QUARANTINE_DIR" "$file" 2>&1 || true)
        
        if echo "$scan_result" | grep -qi "FOUND"; then
            local virus_name
            virus_name=$(echo "$scan_result" | grep -i "FOUND" | awk '{print $2}')
            
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFECTED: $file" >> "$LOG_FILE"
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] Virus: $virus_name" >> "$LOG_FILE"
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] Moved to: $QUARANTINE_DIR" >> "$LOG_FILE"
            
            local file_dir file_name
            file_dir=$(dirname "$file")
            file_name=$(basename "$file")
            
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] Sending alerts..." >> "$LOG_FILE"
            
            # Email alert (background, non-blocking)
            {
                echo "ClamAV ${SCAN_TYPE} Alert
==============================

A virus was detected in real-time on your Mac.

File: $file
Virus: $virus_name
Time: $(date)

The infected file has been moved to quarantine:
$QUARANTINE_DIR

Please review and delete the quarantined file.

---
ClamAV ${SCAN_TYPE} Scanning" | mail -s "URGENT: ClamAV ${SCAN_TYPE} - Virus Detected!" "$EMAIL" 2>/dev/null
            } &
            
            # macOS notification (background)
            osascript -e 'tell application "System Events" to display notification "VIRUS FOUND: '"$file_name"' - Quarantined!" with title "ClamAV '"${SCAN_TYPE}"' Alert" sound name "Basso"' 2>/dev/null &
            
            # Dialog box (background)
            {
                BUTTON_RESULT=$(osascript <<EOF
tell application "System Events"
  activate
  display dialog "ClamAV ${SCAN_TYPE} Alert

A virus was detected in real-time!

File: $file_name
Virus: $virus_name

The file has been moved to quarantine:
$QUARANTINE_DIR

Please review and delete." buttons {"Open Quarantine", "OK"} default button 1 with title "ClamAV ${SCAN_TYPE} Alert" with icon caution giving up after 300
end tell
EOF
                ) 2>/dev/null || echo "OK"
                [[ "$BUTTON_RESULT" == *"Open Quarantine"* ]] && open "$QUARANTINE_DIR"
            } &
            
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] Alerts spawned" >> "$LOG_FILE"
        else
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] Clean" >> "$LOG_FILE"
        fi
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: clamd not running (socket: $CLAMD_SOCKET)" >> "$LOG_FILE"
    fi
}

# ============================================================================
# Main
# ============================================================================

echo "[$(date '+%Y-%m-%d %H:%M:%S')] ============================================" >> "$LOG_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] ClamAV ${SCAN_TYPE} Scanner Started" >> "$LOG_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Monitoring ${#EXISTING_PATHS[@]} paths:" >> "$LOG_FILE"
for p in "${EXISTING_PATHS[@]}"; do
    echo "[$(date '+%Y-%m-%d %H:%M:%S')]   - $p" >> "$LOG_FILE"
done
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Quarantine: $QUARANTINE_DIR" >> "$LOG_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] ============================================" >> "$LOG_FILE"

# Check if we have paths to watch
if [[ ${#EXISTING_PATHS[@]} -eq 0 ]]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: No valid paths to watch!" >> "$LOG_FILE"
    exit 1
fi

# Start watching
# -0: null-delimited output (handles filenames with spaces)
# -r: recursive
# -l 2: latency (seconds) - batch events within 2 seconds
# --event Created --event Updated --event Renamed: only watch relevant events
/opt/local/bin/fswatch -0 -r -l 2 \
    --event Created \
    --event Updated \
    --event Renamed \
    --event MovedTo \
    "${FSWATCH_EXCLUDES[@]}" \
    "${EXISTING_PATHS[@]}" | \
    while IFS= read -r -d '' file; do
        scan_file "$file" &
    done
