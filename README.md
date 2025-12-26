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

 1. Download the [repository](https://github.com/usnistgov/macos_security) and the provided YAML config in this repo, or one from [NIST baselines](https://github.com/usnistgov/macos_security/tree/main/baselines).
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
 3. Generate the configuration file (there should be a `*.mobileconfig` and a `*_compliance.sh` file). Note: do not use root for `generate_guidance.py` as it may affect non-root users. The python script will ask for permissions itself.
```zsh
cd build
mkdir baselines
cd baselines
vi cnssi-1253_cust.yaml

python3 scripts/generate_guidance.py \
        -P \
        -s \
        -p \
    build/baselines/cnssi-1253_cust.yaml
```
 4. Run the compliance script. If there is a previous profile installed, remove it in Settings after this step.
```zsh
sudo zsh build/cnssi-1253_cust/cnssi-1253_cust_compliance.sh
```
 5. First select option 2 in the script, then option 1 to see the report. Skip option 3 for now. The compliance percentage should be around ~15%. Now install the profile if no custom ODVs are applied (one might have to open the Settings app to install the profile):
```zsh
cd build/cnssi-1253_cust/mobileconfigs/unsigned
sudo open cnssi-1253_cust.mobileconfig
```
 6. Optional: Load custom ODV values
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
 6. If custom ODV values are loaded, remove the old configuration profile from Settings, and repeat steps 3 and 4 from above. One way to verify that custom values are working is to go to "Lock screen" in Settings and check if "Require password after screen saver begins..." is set to "immediately"
 7. Run the compliance script again (steps 3 and 4) with options 2, and then 1 in this order. The script should now yield ~80% compliance.
 8. Run option 3 and go through all scripts (select `y` for all settings) to apply settings not covered within the configuration profile.
 9. Run options 2 and 1 yet again. The compliance percentage should be about 95%. In this step, running option 3 will not do anything, because it does everything within its control already, and the script will automatically exit.
 10. Run option 2, copy the outputs, and find all rules that are still failing. Usually it is these two:
```zsh
os_firewall_default_deny_require
system_settings_filevault_enforce
```
 11. Go inside Settings and manually toggle these two options, the first one as "Block all incoming connections" in "Firewall" > "Options", and the second one by searching "Filevault". Further ensure that pf firewall and FileVault are enabled (ALF is enabled by default):
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
 12. The script might still not yield 100% compliance, but all settings should be applied. Restart the device.

**Note** if unwanted banners show up, remove the corresponding files with `sudo rm -rf /Library/Security/PolicyBanner.*`

## 2. ClamAV Setup (MacPorts)
 1. Install ClamAV from MacPorts: `sudo port install clamav-server`. This ClamAV port creates all non-example configurations already. *Important* do NOT execute `sudo port load clamav-server` because doing so will conflict with this guide's startup scripts; also do not give `daemondo` full-disk access because it is unnecessary.
 2. Give the current user database permissions and substitute "admin" with actual username:
```zsh
sudo mkdir -p /opt/local/share/clamav
sudo chown -R admin:staff /opt/local/share/clamav
sudo chmod 755 /opt/local/share/clamav
```
 3. Also give logfile permissions:
```zsh
sudo chown -R admin:staff /opt/local/var/log/clamav
sudo chmod -R 755 /opt/local/var/log/clamav
```
```zsh
sudo vi /opt/local/etc/freshclam.conf

# Uncomment these two
UpdateLogFile /opt/local/var/log/clamav/freshclam.log
NotifyClamd /opt/local/etc/clamd.conf
DatabaseDirectory /opt/local/share/clamav
```
 4. Set up `clamd`:
```zsh
sudo vi /opt/local/etc/clamd.conf

# Uncomment
LocalSocket /opt/local/var/run/clamav/clamd.socket
PidFile /opt/local/var/run/clamav/clamd.pid
Foreground yes
LogFile /opt/local/var/log/clamav/clamd.log
DatabaseDirectory /opt/local/share/clamav
```
 5. Create socket directory and start `clamd`
```zsh
sudo mkdir -p /opt/local/var/run/clamav
sudo chown _clamav:_clamav /opt/local/var/run/clamav
sudo chmod 755 /opt/local/var/run/clamav

sudo mkdir -p /opt/local/var/log/clamav
sudo chown _clamav:_clamav /opt/local/var/log/clamav
sudo chmod 755 /opt/local/var/log/clamav
```
 6. Create daemon:
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
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/clamd-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/clamd-stderr.log</string>
</dict>
</plist>
```
 7. Now that `clamd` is configured, use `clamdscan` over `clamscan` for better performance:
```zsh
sudo vi /opt/local/etc/clamd.conf

# Add to the end
ExcludePath ^/.*\.git
ExcludePath ^/.*/node_modules
ExcludePath ^/.*/Library/Caches
ExcludePath ^/.*\.Trash
```
 8. Update the scan script:
```zsh
sudo mkdir /usr/local/bin 
sudo vi /usr/local/bin/clamav-scan.sh
```
```bash
#!/usr/bin/env bash
set -euo pipefail

# Configuration
LOG_DIR="$HOME/clamav-logs"
QUARANTINE_DIR="$HOME/quarantine"

# Create directories
mkdir -p "$LOG_DIR" "$QUARANTINE_DIR"

# If no arguments, default to Downloads
TARGETS=("${@:-$HOME/Downloads}")

# Check if clamd is running
if [[ -S /opt/local/var/run/clamav/clamd.socket ]]; then
  # Use clamdscan (faster, multi-threaded)
  SCANNER="/opt/local/bin/clamdscan"
  echo "Using clamdscan (daemon mode - faster)"
  
  for TARGET in "${TARGETS[@]}"; do
    echo "Scanning: $TARGET"
    "$SCANNER" --multiscan -i \
      --move="$QUARANTINE_DIR" \
      "$TARGET" \
      -l "$LOG_DIR/scan-$(date +%F).log"
  done
else
  # Fall back to clamscan
  echo "clamd not running, using clamscan (slower)"
  
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
  
  for TARGET in "${TARGETS[@]}"; do
    echo "Scanning: $TARGET"
    "$CLAMSCAN" -r -i \
      --move="$QUARANTINE_DIR" \
      --exclude-dir="\.git" \
      --exclude-dir="node_modules" \
      --exclude-dir="Library/Caches" \
      --exclude-dir="\.Trash" \
      "$TARGET" \
      -l "$LOG_DIR/scan-$(date +%F).log"
  done
fi
```
 9. Run `freshclam` *without sudo*, and the command should run fine with ClamAV updating its database (which might take a while). Next, also give the daemon similar permissions:
```zsh
sudo mkdir -p /opt/local/var/run/clamav
sudo chown -R admin:staff /opt/local/var/run/clamav
sudo chmod 755 /opt/local/var/run/clamav
```
 10. For MacPorts, it defaults to running in the foreground. If one decides to stop here and not implement anything else in this section, change this line in `/opt/local/etc/freshclam.conf` to run silently and not block terminal i/o:
```conf
Foreground no
```
 11. The ClamAV daemon should now run in the background properly with `freshclam -d`
 12. Restart the computer, go to "System Preferences> Security & Privacy> Full Disk Access" and give MacPorts process "daemondo" FDA.
 13. Check if everything is working so far (`com.personal.freshclam` will be implemented in the following sections):
```zsh
sudo launchctl unload /Library/LaunchDaemons/com.personal.clamd.plist
sudo launchctl load /Library/LaunchDaemons/com.personal.clamd.plist

sudo launchctl list | grep com.personal
# Expected output:
# 2993	0	com.personal.clamd

ls -la /opt/local/var/run/clamav/clamd.socket
clamdscan --version
```

**Note** Manual scan commands:
```zsh
clamdscan --multiscan -i ~/Downloads
clamdscan --multiscan -i --move=~/quarantine ~/Downloads
clamscan -r -i ~/Downloads
```

**Note** this guide does not use MacPorts' default scripts because the scripts in this guide bundle launch services, daemons, etc. that are not included in the shipped scripts otherwise. I.e., the "startup items" will not run scan themselves but only vibe in the background, and manually toggling them to do start might collide with the automatic mechanisms in this guide.

### Running as a Launchd service
Instead of running `freshclam -d` as a daemon directly, one can wrap it inside a `launchd` service to trigger it automatically at startup.

 1. Check if there is an instance running. If there is, kill it:
```zsh
sudo launchctl list | grep com.personal.freshclam
-    2    com.personal.freshclam
admin@Device etc % ps aux | grep freshclam
admin            53527   0.0  0.0 435300304   1392 s000  S+   12:39AM   0:00.00 grep freshclam
admin            53360   0.0  0.0 435380864  15440 s000  SN   12:21AM   0:00.09 freshclam -d

sudo kill 53360
sudo rm /opt/local/var/run/clamav/freshclam.pid
```
 2. Turn on the foreground service to prevent freshclam from forking itself automatically (this should be prioritized over the previous section):
```zsh
Foreground yes
```
 3. Create the daemon file:
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
        <string>-d</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/freshclam-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/freshclam-stderr.log</string>
</dict>
</plist>
```
 4. Reload the daemon (unload may throw error if this is the first time running the daemon):
```zsh
sudo launchctl unload /Library/LaunchDaemons/com.personal.freshclam.plist
sudo launchctl load /Library/LaunchDaemons/com.personal.freshclam.plist
```
 5. Verify: the status should be "??" to show that the process is detached from the terminal, and the status code in launchctl should be 0
```zsh
sudo launchctl list | grep com.personal.freshclam
# 3030	0	com.personal.freshclam

sudo launchctl list | grep com.personal          
# 2993	0	com.personal.clamd
# 3030	0	com.personal.freshclam

ps aux | grep freshclam
# admin             3042   0.0  0.0 435299440   1376 s000  S+   11:53PM   0:00.00 grep freshclam
# _clamav           3030   0.0  0.0 435376560  13088   ??  Ss   11:52PM   0:00.04 /opt/local/bin/freshclam -d
```
**Note** macOS may show background app notifications from "Joshua Root" when ClamAV services run. This is normal - Joshua Root is the MacPorts developer who signs the MacPorts packages, and macOS displays the certificate signer's name for background processes.

### Setting Up Daily Scans
 1. Using the scan file in the first section, make it executable instead of being a placeholder:
```zsh
sudo chmod +x /usr/local/bin/clamav-scan.sh
```
 2. Create LaunchDaemon for daily scans, where the `/Users/admin` array should be the directories to scan:
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
        <string>/bin/bash</string>
        <string>/usr/local/bin/clamav-scan.sh</string>
        <string>/Users/admin</string>
        <string>/Users/warren</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>4</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>/var/log/clamscan-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/clamscan-stderr.log</string>
</dict>
</plist>
```
 3. Load the daemon and give appropriate permissions. The daemon runs as the `_clamav` user for security, so final permissions must be set for `_clamav` in step 3. Otherwise, running through the `admin:staff` user is fine.
```zsh
sudo launchctl load /Library/LaunchDaemons/com.personal.clamscan.plist
sudo chown -R _clamav:_clamav /opt/local/share/clamav
sudo chmod 755 /opt/local/share/clamav
```
 4. Restart the system, and after reboot, check if everything works (note: `freshclam.log` may show an error before a restart):
```zsh
sudo launchctl list | grep com.personal.freshclam
# 3030	0	com.personal.freshclam

ps aux | grep freshclam
# admin             3073   0.0  0.0 435300448   1376 s000  S+   11:54PM   0:00.00 grep freshclam
# _clamav           3030   0.0  0.0 435376560  13088   ??  Ss   11:52PM   0:00.04 /opt/local/bin/freshclam -d
```
```zsh
sudo tail -20 /opt/local/var/log/clamav/freshclam.log
```
 5. To restart a service, run either of these depending on the erraneous service:
```zsh
sudo launchctl unload /Library/LaunchDaemons/com.personal.freshclam.plist
sudo launchctl load /Library/LaunchDaemons/com.personal.freshclam.plist
```
```zsh
sudo launchctl unload /Library/LaunchDaemons/com.personal.clamscan.plist
sudo launchctl load /Library/LaunchDaemons/com.personal.clamscan.plist
```

### Testing with EICAR
Verify that ClamAV is working correctly by testing with the EICAR test file (a harmless file designed to test antivirus software):

```zsh
mkdir -p ~/clamav-test && cd ~/clamav-test
curl -L -o eicar.com.txt https://secure.eicar.org/eicar.com.txt
clamdscan -i eicar.com.txt
rm -f eicar.com.txt

# Should see output similar to "eicar.com.txt: Eicar-Test-Signature FOUND"
```
This confirms that ClamAV can detect threats. The EICAR file is not an actual virus, it's a standard test file recognized by all antivirus software.

### Email Notifications (Optional)
Set up email alerts when infections are found in the quarantine directory.
 1. Create the email notification script:
```zsh
mkdir -p ~/scripts
vi ~/scripts/clam-mail
```
```bash
#!/bin/bash
echo "There are new items for review in $HOME/quarantine" | mail -s "URGENT! Clamscan Found Infections!" root
```
```zsh
chmod +x ~/scripts/clam-mail
```
 2. Create the LaunchDaemon that watches the quarantine directory:
```zsh
sudo vi /Library/LaunchDaemons/com.personal.clammail.plist
```
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.personal.clammail</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/admin/scripts/clam-mail</string>
    </array>
    <key>WatchPaths</key>
    <array>
        <string>/Users/admin/quarantine</string>
    </array>
    <key>AbandonProcessGroup</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/clammail.stderr</string>
</dict>
</plist>
```
 3. Load the notification daemon
```zsh
sudo launchctl load /Library/LaunchDaemons/com.personal.clammail.plist
```
 4. Create SASL Password File
```zsh
sudo vi /etc/postfix/sasl_passwd

# Add
[smtp.gmail.com]:587 yjwarrenwang@gmail.com:YOUR_APP_PASSWORD_HERE
```
 2. To generate a Gmail App Password:
  - Go to https://myaccount.google.com/security
  - Enable 2-Step Verification if not already enabled
  - Search for "App passwords"
  - Generate a new app password for "Mail"
  - Use that 16-character password in the file above
 3. Configure postfix
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
 5. Start postfix
```zsh
sudo postfix start
sudo postfix reload
```
 6. If there is a failed queue from previous steps, run this command to clear the queue.
```zsh
sudo postsuper -d ALL
```
 7. Paste this command in cli to send a test email (and check Gmail inbox):
```zsh
echo "Test email from ClamAV" | mail -s "Test Subject" yjwarrenwang@gmail.com
```
 8. Edit the notification script to use actual email:
```zsh
vi ~/scripts/clam-mail
```
```bash
#!/bin/bash
echo "There are new items for review in $HOME/quarantine" | mail -s "URGENT! Clamscan Found Infections!" yjwarrenwang@gmail.com
```

### (Optional) Implementing On-Access Scanning
 > There isn't an official on-access scanning (only on linux) because it requires the Linux `fanotify` kernel API (kernel version ≥ 3.8) to block file access at the kernel level.

 1. Install `fswatch`:
```zsh
sudo port install fswatch
```
 2. Create the on-access scan script:
```zsh
#!/usr/bin/env bash
set -euo pipefail

# Configuration
WATCH_DIRS=(
  "$HOME/Downloads"
  "$HOME/Desktop"
)
LOG_FILE="$HOME/clamav-logs/onaccess-$(date +%F).log"
CLAMD_SOCKET="/opt/local/var/run/clamav/clamd.socket"

# Create log directory
mkdir -p "$(dirname "$LOG_FILE")"

# Function to scan a file
scan_file() {
  local file="$1"
  
  # Skip if file doesn't exist or is a directory
  [[ -f "$file" ]] || return 0
  
  # Log the scan
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Scanning: $file" >> "$LOG_FILE"
  
  # Scan with clamdscan if clamd is running
  if [[ -S "$CLAMD_SOCKET" ]]; then
    local scan_result
    scan_result=$(/opt/local/bin/clamdscan --no-summary "$file" 2>&1 || true)
    
    if echo "$scan_result" | grep -qi "FOUND"; then
      local virus_name
      virus_name=$(echo "$scan_result" | grep -i "FOUND" | awk '{print $2}')
      
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFECTED: $file" >> "$LOG_FILE"
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] Virus: $virus_name" >> "$LOG_FILE"
      
      # Send urgent macOS notification
      osascript -e "display dialog \"ClamAV detected a virus on this device

File: $(basename "$file")
Virus: $virus_name
Location: $(dirname "$file")

Delete this file immediately.\" buttons {\"Open Finder\", \"OK\"} default button 1 with title \"ClamAV Alert\" with icon caution" 2>/dev/null &
      
      # Also send a regular notification
      osascript -e "display notification \"VIRUS FOUND: $(basename "$file") - Please delete immediately!\" with title \"ClamAV Alert\" sound name \"Basso\"" 2>/dev/null || true
      
      # Send email alert
      echo "ClamAV detected a virus on Mac"

File: $file
Virus: $virus_name
Time: $(date)

ACTION REQUIRED:
Please delete this file immediately from Finder.

---
ClamAV On-Access Scanning" | mail -s "ClamAV detected a virus on Mac" yjwarrenwang@gmail.com 2>/dev/null || true
      
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] Alerts sent (email + notification)" >> "$LOG_FILE"
    else
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] Clean" >> "$LOG_FILE"
    fi
  else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: clamd not running" >> "$LOG_FILE"
  fi
}

# Watch directories and scan changed files
echo "[$(date '+%Y-%m-%d %H:%M:%S')] On-Access Scanner Started" >> "$LOG_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Monitoring: ${WATCH_DIRS[*]}" >> "$LOG_FILE"

/opt/local/bin/fswatch -0 -r -e "\.git" -e "node_modules" -e "\.Trash" -e "\.DS_Store" "${WATCH_DIRS[@]}" | \
  while IFS= read -r -d '' file; do
    scan_file "$file"
  done
```
```zsh
sudo chmod +x /usr/local/bin/clamav-onaccess.sh
```
 3. Create LaunchAgent to run as own user (1. ClamAV runs as the `_clamav` user, so it does not make sense to run the script as root, and 2. `fswatch` is not kernel-level, so giving it privilege escalation does not do anything).
```zsh
vi ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist
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
 4. Load the LaunchAgent (note: this command should only show the on-access script because it is not ran as `sudo`).
```
launchctl load ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist
launchctl list | grep clamav-onaccess
ps aux | grep fswatch
```
 5. Reload the service.
```zsh
launchctl unload ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist
launchctl load ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist
```
 6. Run a live test. In two different terminals, run these script and verify that the device and email notification both work:
```zsh
tail -f ~/clamav-logs/onaccess-$(date +%F).log
```
```zsh
cd ~/Downloads
curl -L -o eicar-test.txt https://secure.eicar.org/eicar.com.txt
```
 7. Also run a clean file. The log should show that ClamAV scanned the file, but it did not take any actions.
```zsh
echo "This is a normal file" > ~/Downloads/test.txt
```

> Why tf did I just implement an AV for mac from binaries?

### Clean Up Default MacPorts Services
Since this guide uses its own launchd services, wrap up this setup by removing the symlinks:
```zsh
sudo rm /Library/LaunchDaemons/org.macports.freshclam.plist
sudo rm /Library/LaunchDaemons/org.macports.clamd.plist
sudo rm /Library/LaunchDaemons/org.macports.ClamavScanOnAccess.plist
sudo rm /Library/LaunchDaemons/org.macports.ClamavScanSchedule.plist
```
One can also run this line to verify:
```zsh
sudo launchctl list | grep org.macports
```
If the output is empty, it means that no ClamAV configuration from MacPorts will be automatically loaded, which fits the objective of this section.

<sup>https://paulrbts.github.io/blog/software/2017/08/18/clamav/</sup><br/>
<sup>https://blog.csdn.net/qq_60735796/article/details/156052196</sup>
