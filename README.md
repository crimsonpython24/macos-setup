# MacOS Setup (WIP)

## 0. Basics
### Administrative Account ("Admin")
#### Principles
 - `launchd` should not be modified like `systemctl` as the former is not designed for user tweaks
   - This rule also applies to "UI skins", custom plugins, etc. since they might break with future updates
   - I.e., one should not change any obscure settings (e.g., `defaults write com.apple.something`) unless they know exactly what they are doing

#### App Installation Guidelines
 - Do not use the admin account besides initializing the machine
 - Do not install any application as Admin, as apps should run just fine without being installed from the root directory (i.e. `/Applications`)
   - Said apps will prompt for password if they need privilege escalations regardless
   - Do not move pre-/auto-installed MacOS apps around in Finder, because future updates might break those modifications
 - Only make system-wide configurations (e.g., network interface) or run services such as ClamAV and Santa in Admin
   - If the administrative binaries configured in this guide do not affect the unprivileged user, double-check the writeout because they should
   - Also install security apps (e.g., Murus, pf configurators) in Admin, because they work better with full-system access

### Security Baselines
#### Option 1: NIST Configuration (Recommended)
 - Load NIST's MacOS Security configuration with [CNSSI-1253_high](https://github.com/usnistgov/macos_security/blob/2ac6b9078edf2cc521ca90450111e32de164916a/baselines/cnssi-1253_high.yaml)
   - CNSSI-1253 is the selected baseline in this example as it covers most settings without requiring an antivirus
   - Run the configurator to alter some rules, e.g., disable smart card for those who do not have one

#### Option 2: Manual Configuration
 - If one does not want to load the NIST configuration, they can do the following instead:
   - Enable FileVault, Firewall, and [GateKeeper](https://dev.to/reybis/enable-gatekeeper-macos-1klh)
   - Disable AirDrop, [Remote Login](https://support.apple.com/en-gb/guide/mac-help/mchlp1066/mac), [Remote Desktop](https://support.apple.com/en-za/guide/mac-help/mh11851/mac), and all [remote access](https://support.apple.com/guide/remote-desktop/enable-remote-management-apd8b1c65bd/mac) sharing settings
   - Disable [Bonjour](https://www.tenable.com/audits/items/CIS_Apple_macOS_10.13_v1.1.0_Level_2.audit:d9dcee7e4d2b8d2ee54f437158992d88) and [Guest User](https://discussions.apple.com/thread/253375291?sortBy=rank) if possible
   - Disable location at all times (personal preference; can be adjusted)

### Extra Checklist
 - Terminal
   - Ensure that [Full Security](https://support.apple.com/en-za/guide/mac-help/mchl768f7291/mac), [SIP](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html), and [secure keyboard](https://fig.io/docs/support/secure-keyboard-input) (in Terminal and iTerm) are enabled
   - Use MacPorts [instead of](https://saagarjha.com/blog/2019/04/26/thoughts-on-macos-package-managers/) Brew
   - [Prevent](https://github.com/sunknudsen/guides/tree/main/archive/how-to-protect-mac-computers-from-cold-boot-attacks) cold-boot attacks
 - System Settings
   - Even with NIST parameters active, one can still verify FileVault, Firewall, and related settings in the Settings app
   - Disable automatic accessory access in "Settings -> Privacy & Security -> Accessories"
 - Extra Memos
   - Do not install [unmaintained](https://the-sequence.com/twitch-privileged-helper) applications
   - Avoid [Parallels VM](https://jhftss.github.io/Parallels-0-day/), [Electron-based](https://redfoxsecurity.medium.com/hacking-electron-apps-security-risks-and-how-to-protect-your-application-9846518aa0c0) applications (see a full list [here](https://www.electronjs.org/apps)), and apps needing [Rosetta](https://cyberinsider.com/apples-rosetta-2-exploited-for-bypassing-macos-security-protections/) translation

### Note
This section reflects the "secure, not private" concept in that, although these settings make the OS more secure than the shipped or reinstalled version, this does **not** guarantee privacy from first-party surveillance. 

<sup>https://taoofmac.com/space/howto/switch#best-practices</sup><br/>
<sup>https://support.addigy.com/hc/en-us/articles/4403726652435-Recommended-macOS-Security-Configurations</sup><br/>
<sup>https://news.ycombinator.com/item?id=31864974</sup><br/>
<sup>https://github.com/beerisgood/macOS_Hardening?tab=readme-ov-file</sup>

## 1. NIST Setup
 > For the following sections, all dependencies (Git, Python3) can be installed via MacPorts. Avoid using packages to keep dependency tree clean.

Important: the security compliance project does **not** modify any system behavior on its own. It generates a script that validates if the system reflects the selected policy, and a configuration profile that implements the changes.

 > Unless otherwise specified, all commands here should be ran at the project base.

 1. Download the [repository](https://github.com/usnistgov/macos_security) and the [provided YAML config](https://github.com/crimsonpython24/macos-setup/blob/master/cnssi-1253_cust.yaml) in this repo, or one from [NIST baselines](https://github.com/usnistgov/macos_security/tree/main/baselines). Store the YAML file inside `macos_security-main/build/baselines`
 2. Install dependencies, recommended within a virtual environment.
```zsh
xcode-select --install
sudo port install python314
sudo port select --set python python314
sudo port select --set python3 python314
```
```zsh
cd ~/Desktop/macos_security
python3 -m venv venv
source venv/bin/activate
python3 -m pip install --upgrade pip
pip3 install pyyaml xlwt
```
 3. Optional: Load custom ODV values
```zsh
cat > custom/rules/pwpolicy_minimum_length_enforce.yaml << 'EOF'
odv:
  custom: 12
EOF

cat > custom/rules/pwpolicy_account_lockout_enforce.yaml << 'EOF'
odv:
  custom: 5
EOF

cat > custom/rules/system_settings_screensaver_ask_for_password_delay_enforce.yaml << 'EOF'
odv:
  custom: 0
EOF
```
 4. Generate the configuration file (there should be a `*.mobileconfig` and a `*_compliance.sh` file). Note: do not use root for `generate_guidance.py` as it may affect non-root users. The python script will ask for permissions itself.
```zsh
python3 scripts/generate_guidance.py \
        -P \
        -s \
        -p \
    build/baselines/cnssi-1253_cust.yaml
```
 5. Run the compliance script. If there is a previous profile installed, remove it in Settings before this step.
```zsh
sudo zsh build/cnssi-1253_cust/cnssi-1253_cust_compliance.sh
```
 6. First select option 2 in the script, then option 1 to see the report. Skip option 3 for now. The compliance percentage should be around 15%. Exit the tool.
 7. Install the configuration profile (one might have to open the Settings app to install the profile):
```zsh
# Re-run this line if any of the YAML fields are edited (e.g., new ODVs)
python3 scripts/generate_guidance.py \
        -P \
        -s \
        -p \
    build/baselines/cnssi-1253_cust.yaml
```
```zsh
cd build/cnssi-1253_cust/mobileconfigs/unsigned
sudo open cnssi-1253_cust.mobileconfig
```
 8. If applicable, one way to verify that custom values are working is to go to "Lock screen" in Settings and check if "Require password after screen saver begins..." is set to "immediately", as this guide overwrites the default value for that field.
 9. If not already, exit and run the compliance script again (step 7) with options 2, then 1 in that order. The script should now yield ~80% compliance.
```zsh
sudo zsh build/cnssi-1253_cust/cnssi-1253_cust_compliance.sh
```
 10. Run option 3 and go through all scripts (select `y` for all settings) to apply settings not covered within the configuration profile. There will be a handful of them.
 11. Exit the script and run options 2 and 1 yet again. The compliance percentage should be about 95%. In this step, running option 3 will not do anything, because it does everything within its control already, and the script will automatically return to the main menu.
 12. Run option 2, copy the outputs, and find all rules that are still failing. Usually it is these two:
```zsh
os_firewall_default_deny_require
system_settings_filevault_enforce
```
 13. Go inside Settings and manually toggle these two options, the first one as "Block all incoming connections" in "Firewall" > "Options", and the second one by searching "Filevault". Further ensure that pf firewall and FileVault are enabled (ALF is enabled by default):
```zsh
ls includes/enablePF-mscp.sh
sudo bash includes/enablePF-mscp.sh

sudo pfctl -a '*' -sr | grep "block drop in all"
# should output smt like "block drop in all" i.e. default deny all incoming
sudo pfctl -s info
```
```zsh
sudo fdesetup status
```
 14. Note from previous step: one might encounter these two warnings
   - "No ALTQ support in kernel" / "ALTQ related functions disabled": ALTQ is a legacy traffic shaping feature that has been disabled in modern macOS, which does not affect pf firewall at all
   - "pfctl: DIOCGETRULES: Invalid argument": this occurs when pfctl queries anchors that do not support certain operations, but custom rules in this guide are still loaded (can still see `block drop in all`).
 15. The script might still not yield 100% compliance, but all settings should be applied. Restart the device.

**Note** if unwanted banners show up, remove the corresponding files with `sudo rm -rf /Library/Security/PolicyBanner.*`

## 2. ClamAV Setup (MacPorts)

> **Note on Email Notifications:** The scan scripts include email alerting, but this is **optional**. If email is not configured, the scripts will still work - alerts simply won't be sent. To enable email notifications, complete the "Email Notifications Setup" section later in this guide.

### Part 1: Base ClamAV Installation
 1. Install ClamAV from MacPorts: `sudo port install clamav-server`. This ClamAV port creates all non-example configurations already. *Important* do NOT execute `sudo port load clamav-server` because doing so will conflict with this guide's startup scripts; also do not give `daemondo` full-disk access because it is unnecessary.
 2. Give the current user database and logfile permissions (substitute "admin" with actual username):
```zsh
sudo mkdir -p /opt/local/share/clamav
sudo chown -R admin:staff /opt/local/share/clamav
sudo chmod 755 /opt/local/share/clamav

sudo mkdir -p /opt/local/var/log/clamav
sudo chown -R admin:staff /opt/local/var/log/clamav
sudo chmod 755 /opt/local/var/log/clamav

sudo mkdir -p /opt/local/var/run/clamav
sudo chown -R admin:staff /opt/local/var/run/clamav
sudo chmod 755 /opt/local/var/run/clamav
```
 3. Set up Freshclam:
```zsh
sudo vi /opt/local/etc/freshclam.conf

# Comment out:
# Example

# Uncomment
UpdateLogFile /opt/local/var/log/clamav/freshclam.log
NotifyClamd /opt/local/etc/clamd.conf
DatabaseDirectory /opt/local/share/clamav
```
```zsh
touch /opt/local/var/log/clamav/freshclam.log
sudo chown admin:staff /opt/local/var/log/clamav/freshclam.log
sudo chmod 644 /opt/local/var/log/clamav/freshclam.log
```
 4. Set up `clamd`:
```zsh
sudo vi /opt/local/etc/clamd.conf

# Comment out:
# Example

# Uncomment
LocalSocket /opt/local/var/run/clamav/clamd.socket
PidFile /opt/local/var/run/clamav/clamd.pid
Foreground yes
LogFile /opt/local/var/log/clamav/clamd.log
DatabaseDirectory /opt/local/share/clamav
LogVerbose yes
LogFileMaxSize 10M

# Add to end (exclusions for performance)
ExcludePath ^/.*/\.git/
ExcludePath ^/.*/node_modules/
ExcludePath ^/.*/Library/Caches
ExcludePath ^/.*\.Trash
ExcludePath ^/.*/Library/Application Support/Knowledge
ExcludePath ^/.*/Library/Application Support/com.apple.TCC
ExcludePath ^/.*/Library/Application Support/AddressBook
ExcludePath ^/.*/Library/Application Support/FaceTime
ExcludePath ^/.*/Library/Application Support/CallHistoryDB
ExcludePath ^/.*/Library/Autosave Information
ExcludePath ^/.*\.viminfo$
ExcludePath ^/.*\.bnnsir$
ExcludePath ^/.*/Library/Group Containers
ExcludePath ^/.*/Library/Daemon Containers
ExcludePath ^/.*/Library/Biome
```
 5. Run `freshclam` *without sudo* to download the initial virus database (this may take a while):
```zsh
freshclam
```
 6. Create clamd daemon:
```zsh
sudo vi /Library/LaunchDaemons/com.personal.clamd.plist
```
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.personal.clamd</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/local/sbin/clamd</string>
    </array>
    <key>UserName</key>
    <string>admin</string>
    <key>GroupName</key>
    <string>staff</string>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/opt/local/var/log/clamav/clamd-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/opt/local/var/log/clamav/clamd-stderr.log</string>
</dict>
</plist>
```
```zsh
sudo launchctl load /Library/LaunchDaemons/com.personal.clamd.plist
```
 7. Create freshclam daemon (for automatic database updates):
```zsh
sudo vi /Library/LaunchDaemons/com.personal.freshclam.plist
```
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.personal.freshclam</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/local/bin/freshclam</string>
    </array>
    <key>UserName</key>
    <string>admin</string>
    <key>GroupName</key>
    <string>staff</string>
    <key>StartInterval</key>
    <integer>3600</integer>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/opt/local/var/log/clamav/freshclam-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/opt/local/var/log/clamav/freshclam-stderr.log</string>
</dict>
</plist>
```
```zsh
sudo launchctl load /Library/LaunchDaemons/com.personal.freshclam.plist
```
 8. **Checkpoint** - Verify base installation:
```zsh
# Check daemons are running
sudo launchctl list | grep com.personal
#   XXXX	0	com.personal.clamd
#   XXXX	0	com.personal.freshclam

# Check socket exists
ls -la /opt/local/var/run/clamav/clamd.socket
# srw-rw-rw-  1 admin  staff ...

# Check ClamAV version and database
clamdscan --version
# ClamAV X.X.X/XXXXX/...

# Test scan with EICAR
cd ~/Downloads
curl -L -o eicar-test.txt https://secure.eicar.org/eicar.com.txt
clamdscan -i eicar-test.txt
# Expected: eicar-test.txt: Eicar-Test-Signature FOUND
rm -f eicar-test.txt
```

**Note** macOS may show background app notifications from "Joshua Root" when ClamAV services run. This is normal - Joshua Root is the MacPorts developer who signs the packages.

### Part 2: Daily Scan Setup
 1. Create the daily scan script:
```zsh
sudo mkdir -p /usr/local/bin 
sudo vi /usr/local/bin/clamav-scan.sh
```
```bash
#!/usr/bin/env bash
set -euo pipefail

# Configuration
LOG_DIR="$HOME/clamav-logs"
QUARANTINE_DIR="$HOME/quarantine"
EMAIL="yjwarrenwang@gmail.com"  # Change to own email
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
INFECTED_COUNT=$(grep -i "Infected files:" "$SCAN_RESULT_FILE" 2>/dev/null | tail -1 | awk '{print $3}' | tr -d '[:space:]' || echo "")
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
  
  # Brief wait for email queue (non-blocking after 30s)
  for i in {1..30}; do
    if mailq 2>/dev/null | grep -q "Mail queue is empty"; then
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] Email sent successfully" | tee -a "$SCAN_LOG"
      break
    fi
    sleep 1
  done
  
  # Show notifications in background (non-blocking)
  (
    osascript -e "display notification \"$INFECTED_COUNT infected file(s) found and quarantined!\" with title \"ClamAV ${SCAN_TYPE} Alert\" sound name \"Basso\"" 2>/dev/null || true
    
    BUTTON_RESULT=$(osascript -e "display dialog \"ClamAV ${SCAN_TYPE} Alert

$INFECTED_COUNT infected file(s) detected and moved to quarantine!

Location: $QUARANTINE_DIR

Please review and delete immediately.\" buttons {\"Open Quarantine\", \"OK\"} default button 1 with title \"ClamAV ${SCAN_TYPE} Alert\" with icon caution giving up after 300" -e "button returned of result" 2>/dev/null || echo "OK")
    
    if [[ "$BUTTON_RESULT" == "Open Quarantine" ]]; then
      open "$QUARANTINE_DIR"
    fi
  ) &
  
  disown
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Alerts sent" | tee -a "$SCAN_LOG"
else
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Scan complete - No infections found" | tee -a "$SCAN_LOG"
fi

# Cleanup
rm -f "$SCAN_RESULT_FILE"
```
```zsh
sudo chmod +x /usr/local/bin/clamav-scan.sh
```
 2. Create a permission wrapper (because giving `/bin/bash` FDA is insecure):
```zsh
sudo vi /usr/local/bin/clamav-wrapper.c
```
```c
#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    char *args[] = {"/bin/bash", "/usr/local/bin/clamav-scan.sh", "/Users/admin", NULL};
    execv("/bin/bash", args);
    perror("execv failed");
    return 1;
}
```
```zsh
sudo gcc -o /usr/local/bin/clamav-wrapper /usr/local/bin/clamav-wrapper.c
sudo chmod +x /usr/local/bin/clamav-wrapper
```
 3. Create LaunchDaemon for daily scans (runs at 4am):
```zsh
sudo vi /Library/LaunchDaemons/com.personal.clamscan.plist
```
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.personal.clamscan</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/clamav-wrapper</string>
    </array>
    <key>UserName</key>
    <string>admin</string>
    <key>GroupName</key>
    <string>staff</string>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>4</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>/opt/local/var/log/clamav/clamscan-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/opt/local/var/log/clamav/clamscan-stderr.log</string>
</dict>
</plist>
```
```zsh
sudo launchctl load /Library/LaunchDaemons/com.personal.clamscan.plist
```
 4. Grant Full Disk Access. Go to **Settings > Privacy & Security > Full Disk Access** and add:
```
/usr/local/bin/clamav-wrapper
/opt/local/bin/clamdscan
/opt/local/bin/clamscan
/opt/local/sbin/clamd
```
 5. **Checkpoint** - Verify daily scan setup (also re-verifies Part 1):
```zsh
# Re-verify daemons from Part 1
sudo launchctl list | grep com.personal
# Expected: Three entries (clamd, freshclam, clamscan) with exit code 0

# Test daily scan manually
curl -L -o ~/Downloads/eicar-daily-test.txt https://secure.eicar.org/eicar.com.txt
/usr/local/bin/clamav-scan.sh ~/Downloads
# Expected: 
#   - Scan output with statistics
#   - "1 infected file(s) found" message
#   - File moved to ~/quarantine/
#   - Dialog notification appears
#   - Email NOT sent yet (that's OK - email setup is next)

# Check log was created
tail -20 ~/clamav-logs/scan-$(date +%F).log
# Expected: Scan summary with "Infected files: 1"

# Check quarantine
ls ~/quarantine/
# Expected: eicar-daily-test.txt (or .001 if run multiple times)
```

### Part 3: Email Notifications (Optional)
> Skip this section if you don't want email alerts. The scan scripts will work fine without email - alerts simply won't be sent.

 1. Create SASL password file:
```zsh
sudo vi /etc/postfix/sasl_passwd

# Add (replace with your email and app password):
[smtp.gmail.com]:587 yjwarrenwang@gmail.com:YOUR_APP_PASSWORD_HERE
```
 2. To generate a Gmail App Password:
   - Go to https://myaccount.google.com/security
   - Enable 2-Step Verification if not already enabled
   - Search for "App passwords"
   - Generate a new app password for "Mail"
   - Use that 16-character password in the file above
 3. Configure postfix:
```zsh
sudo vi /etc/postfix/main.cf

# Add these lines at the end:
relayhost = [smtp.gmail.com]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_sasl_mechanism_filter = plain
smtp_use_tls = yes
smtp_tls_security_level = encrypt
smtp_tls_CAfile = /etc/ssl/cert.pem
smtp_address_preference = ipv4
```
 4. Secure and hash password file:
```zsh
sudo chmod 600 /etc/postfix/sasl_passwd
sudo postmap /etc/postfix/sasl_passwd
```
 5. Start postfix:
```zsh
sudo postfix start
sudo postfix reload
```
 6. **Checkpoint** - Verify email AND re-verify Parts 1-2:
```zsh
# Test email directly
echo "Test email from ClamAV setup" | mail -s "ClamAV Test" yjwarrenwang@gmail.com
sleep 5
mailq
# Expected: "Mail queue is empty"
# Check your Gmail inbox for the test email

# Re-verify all daemons
sudo launchctl list | grep com.personal
# Expected: Three entries with exit code 0

# Full integration test with email
curl -L -o ~/Downloads/eicar-email-test.txt https://secure.eicar.org/eicar.com.txt
/usr/local/bin/clamav-scan.sh ~/Downloads
# Expected:
#   - Scan completes
#   - Dialog notification appears
#   - Email IS sent this time (check inbox)
#   - Log shows "Email sent successfully"

tail -10 ~/clamav-logs/scan-$(date +%F).log
# Expected: "Email sent successfully" in output
```

### Part 4: On-Access Scanning (Optional)
> There isn't official on-access scanning on macOS (only Linux via `fanotify`). This uses `fswatch` as a workaround for real-time file monitoring.

 1. Install `fswatch`:
```zsh
sudo port install fswatch
```
 2. Create the on-access scan script:
```zsh
sudo vi /usr/local/bin/clamav-onaccess.sh
```
```bash
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
```
```zsh
sudo chmod +x /usr/local/bin/clamav-onaccess.sh
```
 3. Create LaunchAgent (runs as user, not system):
```zsh
mkdir -p ~/Library/LaunchAgents
vi ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist
```
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.personal.clamav-onaccess</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/clamav-onaccess.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/clamav-onaccess-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/clamav-onaccess-stderr.log</string>
</dict>
</plist>
```
 4. Load the LaunchAgent:
```zsh
launchctl load ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist
```
 5. **Checkpoint** - Full system verification (verifies everything):
```zsh
# === Verify all daemons ===
sudo launchctl list | grep com.personal
# Expected: clamd, freshclam, clamscan (3 entries, exit code 0)

launchctl list | grep clamav-onaccess
# Expected: com.personal.clamav-onaccess with PID

ps aux | grep fswatch | grep -v grep
# Expected: fswatch process running

# === Verify clamd socket ===
ls -la /opt/local/var/run/clamav/clamd.socket
# Expected: socket file exists

# === Test on-access scanning ===
# Terminal 1:
tail -f ~/clamav-logs/onaccess-$(date +%F).log

# Terminal 2:
cd ~/Downloads
curl -L -o eicar-onaccess-test.txt https://secure.eicar.org/eicar.com.txt
# Expected in Terminal 1:
#   - "Scanning: .../eicar-onaccess-test.txt"
#   - "INFECTED: ..."
#   - "Alerts spawned"
# Expected on screen:
#   - Notification appears
#   - Dialog appears with "ClamAV On-Access Alert"
#   - Email received (if configured)

# === Test clean file (should not alert) ===
echo "normal content" > ~/Downloads/clean-test.txt
# Expected in log: "Clean"

# === Verify email (if configured) ===
mailq
# Expected: "Mail queue is empty" (emails sent)

# === Check all logs exist ===
ls -la ~/clamav-logs/
# Expected: scan-YYYY-MM-DD.log and onaccess-YYYY-MM-DD.log
```
 6. Test with clean file:
```zsh
echo "This is a normal file" > ~/Downloads/clean-file-test.txt
tail -5 ~/clamav-logs/onaccess-$(date +%F).log
# Expected: Shows "Clean" for clean-file-test.txt
```

### Cleanup: Remove Default MacPorts Services

Remove MacPorts' default symlinks to avoid conflicts:
```zsh
sudo rm -f /Library/LaunchDaemons/org.macports.freshclam.plist
sudo rm -f /Library/LaunchDaemons/org.macports.clamd.plist
sudo rm -f /Library/LaunchDaemons/org.macports.ClamavScanOnAccess.plist
sudo rm -f /Library/LaunchDaemons/org.macports.ClamavScanSchedule.plist

# Verify none are loaded
sudo launchctl list | grep org.macports
# Should be empty
```

### Quick Reference: Restart Commands
If something isn't working, restart the relevant service:
```zsh
# Restart clamd
sudo launchctl unload /Library/LaunchDaemons/com.personal.clamd.plist
sudo launchctl load /Library/LaunchDaemons/com.personal.clamd.plist

# Restart freshclam
sudo launchctl unload /Library/LaunchDaemons/com.personal.freshclam.plist
sudo launchctl load /Library/LaunchDaemons/com.personal.freshclam.plist

# Restart on-access
launchctl unload ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist
launchctl load ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist

# Trigger daily scan manually
sudo launchctl start com.personal.clamscan
```

### Quick Reference: Log Locations
```zsh
# Daily scan log
~/clamav-logs/scan-$(date +%F).log

# On-access log  
~/clamav-logs/onaccess-$(date +%F).log

# ClamAV daemon log
/opt/local/var/log/clamav/clamd.log

# Freshclam log
/opt/local/var/log/clamav/freshclam.log
```

<sup>https://paulrbts.github.io/blog/software/2017/08/18/clamav/</sup><br/>
<sup>https://blog.csdn.net/qq_60735796/article/details/156052196</sup>
