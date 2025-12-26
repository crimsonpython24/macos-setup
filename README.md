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
 3. Run the compliance script. If there is a previous profile installed, remove it in Settings after this step.
```zsh
sudo zsh build/cnssi-1253_cust/cnssi-1253_cust_compliance.sh
```
 4. First select option 2 in the script, then option 1 to see the report. Skip option 3 for now. The compliance percentage should be around ~15%. Now install the profile (one might have to open the Settings app to install the profile):
```zsh
cd build/cnssi-1253_cust/mobileconfigs/unsigned
sudo open cnssi-1253_cust.mobileconfig
```
 5. Optional: Load custom ODV values
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
 10. Go inside Settings and manually toggle these four options. The script might not yield 100% compliance, but all settings should be applied. Restart the device.

## 2. ClamAV Setup (MacPorts)
 1. Install ClamAV from MacPorts: `sudo port install clamav-server`. This ClamAV port creates all non-example configurations already.
 2. Give the current user database permissions and substitute "admin" with actual username:
```
sudo mkdir -p /opt/local/share/clamav
sudo chown -R admin:staff /opt/local/share/clamav
sudo chmod 755 /opt/local/share/clamav
```
 3. Also give logfile permissions:
```
sudo chown -R admin:staff /opt/local/var/log/clamav
sudo chmod -R 755 /opt/local/var/log/clamav
```
```
sudo vi /opt/local/etc/freshclam.conf

# Uncomment
UpdateLogFile /var/log/freshclam.log
```
 4. The `freshclam` command should work fine now. Lastly, also give the daemon permissions:
```
sudo mkdir -p /opt/local/var/run/clamav
sudo chown -R admin:staff /opt/local/var/run/clamav
sudo chmod 755 /opt/local/var/run/clamav
```
 5. For MacPorts, it defaults to running in the foreground. Change this line in `/opt/local/etc/freshclam.conf`:
```
Foreground no
```
 6. The ClamAV daemon should now run in the background properly with `freshclam -d`

### Running as a Launchd service
Instead of running `freshclam -d` as a daemon directly, one can wrap it inside a `launchd` service to trigger it automatically at startup.

 1. Check if there is an instance running. If there is, kill it:
```
admin@Device etc % sudo launchctl list | grep com.personal.freshclam
-    2    com.personal.freshclam
admin@Device etc % ps aux | grep freshclam
admin            53527   0.0  0.0 435300304   1392 s000  S+   12:39AM   0:00.00 grep freshclam
admin            53360   0.0  0.0 435380864  15440 s000  SN   12:21AM   0:00.09 freshclam -d

sudo kill 53360
sudo rm /opt/local/var/run/clamav/freshclam.pid
```
 2. Turn on the foreground service to prevent freshclam from forking itself automatically (this should be prioritized over the previous section):
```
Foreground yes
```
 3. Create the daemon file:
```
sudo vi /Library/LaunchDaemons/com.personal.freshclam.plist
```
```
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
 4. Reload the daemon
```
sudo launchctl unload /Library/LaunchDaemons/com.personal.freshclam.plist
sudo launchctl load /Library/LaunchDaemons/com.personal.freshclam.plist
```
 5. Verify: the status should be "??" to show that the process is detached from the terminal, and the status code in launchctl should be 0
```
% sudo launchctl list | grep com.personal.freshclam
53560	0	com.personal.freshclam
admin@Device etc % ps aux | grep freshclam
admin            53567   0.0  0.0 435299824   1392 s000  S+   12:46AM   0:00.00 grep freshclam
_clamav          53560   0.0  0.0 435377360  13280   ??  Ss   12:41AM   0:00.05 /opt/local/bin/freshclam -d
```
```
% sudo launchctl list | grep com.personal.freshclam
53560	0	com.personal.freshclam
```

### Setting Up Daily Scans
 1. Edit the following file:
```
sudo mkdir /usr/local/bin/
sudo vi /usr/local/bin/clamav-scan.sh
```
```
#!/usr/bin/env bash
set -euo pipefail

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

# Configuration
LOG_DIR="$HOME/clamav-logs"
QUARANTINE_DIR="$HOME/quarantine"

# Create directories
mkdir -p "$LOG_DIR" "$QUARANTINE_DIR"

# If no arguments, default to Downloads
TARGETS=("${@:-$HOME/Downloads}")

# Scan each target
for TARGET in "${TARGETS[@]}"; do
  echo "Scanning: $TARGET"
  "$CLAMSCAN" -r -i \
    --move="$QUARANTINE_DIR" \
    --exclude-dir="\.git" \
    --exclude-dir="node_modules" \
    "$TARGET" \
    -l "$LOG_DIR/scan-$(date +%F).log"
done
```
```
sudo chmod +x /usr/local/bin/clamav-scan.sh
```
 2. Create LaunchDaemon for daily scans, where the `/Users/admin` array should be the directories to scan:
```
sudo vi /Library/LaunchDaemons/com.personal.clamscan.plist
```
```
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
 3. Load the daemon and give appropriate permissions. Note: the daemon runs as the `_clamav` user for security, so final permissions must be set for `_clamav` in step 3. Otherwise, running through the `admin:staff` user is fine.
```
sudo launchctl load /Library/LaunchDaemons/com.personal.clamscan.plist
sudo chown -R _clamav:_clamav /opt/local/share/clamav
sudo chmod 755 /opt/local/share/clamav
```
 4. Restart the system and check if everything works:
```
sudo launchctl list | grep com.personal.freshclam

Expected output:
12345	0	com.personal.freshclam
```
```
ps aux | grep freshclam

Expected output:
_clamav          12345   0.0  0.0  ... /opt/local/bin/freshclam -d
```
```
tail -20 /opt/local/var/log/clamav/freshclam.log
```
 5. To restart a service, run either of these depending on the erraneous service:
```
sudo launchctl unload /Library/LaunchDaemons/com.personal.freshclam.plist
sudo launchctl load /Library/LaunchDaemons/com.personal.freshclam.plist
```
```
sudo launchctl unload /Library/LaunchDaemons/com.personal.clamscan.plist
sudo launchctl load /Library/LaunchDaemons/com.personal.clamscan.plist
```

### Cleanup Default MacPorts Services
Since this guide uses its own launchd services, wrap up this setup by removing the symlinks:
```
sudo rm /Library/LaunchDaemons/org.macports.freshclam.plist
sudo rm /Library/LaunchDaemons/org.macports.clamd.plist
sudo rm /Library/LaunchDaemons/org.macports.ClamavScanOnAccess.plist
sudo rm /Library/LaunchDaemons/org.macports.ClamavScanSchedule.plist
```
One can also run this line to verify:
```
sudo launchctl list | grep org.macports
```
If the output is empty, it means that no ClamAV configuration from MacPorts will be automatically loaded, which fits the objective of this section.

<sup>https://paulrbts.github.io/blog/software/2017/08/18/clamav/</sup><br/>
<sup>https://blog.csdn.net/qq_60735796/article/details/156052196</sup>
