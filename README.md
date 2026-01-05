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

 1. Download the [repository](https://github.com/usnistgov/macos_security) and the [provided YAML config](https://github.com/crimsonpython24/macos-setup/blob/master/cnssi-1253_cust.yaml) in this repo, or one from [NIST baselines](https://github.com/usnistgov/macos_security/tree/main/baselines). Store the YAML file inside `macos_security-main/build/baselines`.
```zsh
cd build
mkdir baselines && cd baselines
sudo vi cnssi-1253_cust.yaml
```
 2. Ensure that the `macos_security-*` branch downloaded matches the OS version, e.g., `macos_security-tahoe`.
 3. Install dependencies, recommended within a virtual environment.
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
 4. Optional: Load custom ODV values
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
 5. Generate the configuration file (there should be a `*.mobileconfig` and a `*_compliance.sh` file). Note: do not use root for `generate_guidance.py` as it may affect non-root users. The python script will ask for permissions itself (keep running the script even if it kills itself; it will eventually get all permissions).
```zsh
python3 scripts/generate_guidance.py \
        -P \
        -s \
        -p \
    build/baselines/cnssi-1253_cust.yaml
```
 6. Run the compliance script. If there is a previous profile installed, remove it in Settings before this step.
```zsh
sudo zsh build/cnssi-1253_cust/cnssi-1253_cust_compliance.sh
```
 7. First select option 2 in the script, then option 1 to see the report. Skip option 3 for now. The compliance percentage should be around 15%. Exit the tool.
 8. Install the configuration profile (one might have to open the Settings app to install the profile):
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
 9. After installing the profile, one way to verify that custom values are working is to go to "Lock screen" in Settings and check if "Require password after screen saver begins..." is set to "immediately", as this guide overwrites the default value for that field.
 10. If not already, exit and run the compliance script again (step 7) with options 2, then 1 in that order. The script should now yield ~80% compliance.
```zsh
sudo zsh build/cnssi-1253_cust/cnssi-1253_cust_compliance.sh
```
 11. Run option 3 and go through all scripts (select `y` for all settings) to apply settings not covered within the configuration profile. There will be a handful of them.
 12. Exit the script and run options 2 and 1 yet again. The compliance percentage should be about 95%. In this step, running option 3 will not do anything, because it does everything within its control already, and the script will automatically return to the main menu.
 13. Run option 2, copy the outputs, and find all rules that are still failing. Usually it is these two:
```zsh
os_firewall_default_deny_require
system_settings_filevault_enforce
```
 14. Go inside Settings and manually toggle these two options, the first one as "Block all incoming connections" in "Network" > "Firewall" > "Options", and the second one by enabling "Filevault" under "Privacy and Security". Further ensure that pf firewall and FileVault are enabled (ALF is enabled by default):
```zsh
ls includes/enablePF-mscp.sh
sudo bash includes/enablePF-mscp.sh

sudo pfctl -a '*' -sr | grep "block drop in all"
# should output smt like "block drop in all" i.e. default deny all incoming
sudo pfctl -s info
```
```
# checks filevault
sudo fdesetup status
```
 15. Note from previous step: one might encounter these two warnings
   - "No ALTQ support in kernel" / "ALTQ related functions disabled": ALTQ is a legacy traffic shaping feature that has been disabled in modern macOS, which does not affect pf firewall at all
   - "pfctl: DIOCGETRULES: Invalid argument": this occurs when pfctl queries anchors that do not support certain operations, but custom rules in this guide are still loaded (can still see `block drop in all`).
 16. The script should yield 100% compliance. Restart the device.

**Note** if unwanted banners show up, remove the corresponding files with `sudo rm -rf /Library/Security/PolicyBanner.*`

## 2. ClamAV Setup (MacPorts) - Multi-User Configuration

> **Note on Email Notifications:** The scan scripts include email alerting, but this is **optional**. If email is not configured, the scripts will still work - alerts simply won't be sent. To enable email notifications, complete the "Email Notifications Setup" section later in this guide.

> **Multi-User Note:** This setup configures ClamAV to protect both the `admin` and `warren` (unprivileged) accounts. System daemons run as `root`, while on-access scanning runs per-user.

### Part 1: Base ClamAV Installation
 1. Install ClamAV from MacPorts: `sudo port install clamav-server`. This ClamAV port creates all non-example configurations already. *Important* do NOT execute `sudo port load clamav-server` because doing so will conflict with this guide's startup scripts; also do not give `daemondo` full-disk access because it is unnecessary.
 2. Create directories with root ownership (system daemons run as root):
```zsh
sudo mkdir -p /opt/local/share/clamav
sudo chown -R root:wheel /opt/local/share/clamav
sudo chmod 755 /opt/local/share/clamav

sudo mkdir -p /opt/local/var/log/clamav
sudo chown -R root:wheel /opt/local/var/log/clamav
sudo chmod 755 /opt/local/var/log/clamav

sudo mkdir -p /opt/local/var/run/clamav
sudo chown -R root:wheel /opt/local/var/run/clamav
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
sudo touch /opt/local/var/log/clamav/freshclam.log
sudo chown root:wheel /opt/local/var/log/clamav/freshclam.log
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
DatabaseOwner root
LogVerbose yes
LogRotate yes
LogFileMaxSize 10M

# Add for multi-user access (allows all users to connect to clamd socket)
LocalSocketMode 666

# Add to end (exclusions for performance)
ExcludePath ^/Users/.*/\.git/
ExcludePath ^/Users/.*/node_modules/
ExcludePath ^/Users/.*/Library/Caches/
ExcludePath ^/Users/.*/\.Trash/
ExcludePath ^/Users/.*/Library/Application Support/Knowledge/
ExcludePath ^/Users/.*/Library/Application Support/com\.apple\.TCC/
ExcludePath ^/Users/.*/Library/Application Support/AddressBook/
ExcludePath ^/Users/.*/Library/Application Support/FaceTime/
ExcludePath ^/Users/.*/Library/Application Support/CallHistoryDB/
ExcludePath ^/Users/.*/Library/Autosave Information/
ExcludePath ^/Users/.*/\.viminfo$
ExcludePath ^/Users/.*/\.bnnsir$
ExcludePath ^/Users/.*/Library/Group Containers/
ExcludePath ^/Users/.*/Library/Daemon Containers/
ExcludePath ^/Users/.*/Library/Biome/
ExcludePath ^/private/var/folders/
ExcludePath ^/System/
ExcludePath ^/Users/.*/Library/Containers/.*/\.com\.apple\.containermanagerd\.metadata\.plist$
ExcludePath ^/Users/.*/Library/Preferences/com\.apple\.AddressBook\.plist$
ExcludePath ^/Users/.*/Library/Preferences/com\.apple\.homed.*\.plist$
ExcludePath ^/Users/.*/Library/Preferences/com\.apple\.MobileSMS\.plist$
ExcludePath ^/Users/.*/quarantine/
ExcludePath ^/var/root/quarantine/
```
 5. Run `freshclam` to download the initial virus database (this may take a while). If it shows `WARNING: Clamd was NOT notified: Can't connect to clamd through /opt/local/var/run/clamav/clamd.socket: No such file or directory`, keep proceeding until step 8. This command requires sudo beacuse it runs across users as `root`.
```zsh
sudo freshclam
```
 6. Wrap `clamd` inside an application to give it FDA access (MacOS Tahoe 26+, remember to give FDA in Settings after this step):
```zsh
sudo mkdir -p /Applications/ClamAVDaemon.app/Contents/MacOS

sudo tee /Applications/ClamAVDaemon.app/Contents/MacOS/ClamAVDaemon << 'EOF'
#!/bin/bash
exec /opt/local/sbin/clamd "$@"
EOF

sudo chmod +x /Applications/ClamAVDaemon.app/Contents/MacOS/ClamAVDaemon

sudo tee /Applications/ClamAVDaemon.app/Contents/Info.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>ClamAVDaemon</string>
    <key>CFBundleIdentifier</key>
    <string>com.personal.clamav-daemon</string>
    <key>CFBundleName</key>
    <string>ClamAVDaemon</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
</dict>
</plist>
EOF
```
 7. Also wrap clamdscan inside an app for FDA:
```zsh
sudo mkdir -p /Applications/ClamDScan.app/Contents/MacOS

sudo tee /Applications/ClamDScan.app/Contents/MacOS/ClamDScan << 'EOF'
#!/bin/bash
exec /opt/local/bin/clamdscan "$@"
EOF

sudo chmod +x /Applications/ClamDScan.app/Contents/MacOS/ClamDScan

sudo tee /Applications/ClamDScan.app/Contents/Info.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>ClamDScan</string>
    <key>CFBundleIdentifier</key>
    <string>com.personal.clamdscan</string>
    <key>CFBundleName</key>
    <string>ClamDScan</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
</dict>
</plist>
EOF
```
 8. Create clamd daemon (runs as root for system-wide protection):
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
        <string>/Applications/ClamAVDaemon.app/Contents/MacOS/ClamAVDaemon</string>
    </array>
    <key>UserName</key>
    <string>root</string>
    <key>GroupName</key>
    <string>wheel</string>
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
 9. Create freshclam daemon (for automatic database updates, runs as root):
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
    <string>root</string>
    <key>GroupName</key>
    <string>wheel</string>
    <key>StartInterval</key>
    <integer>3600</integer>
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
 10. Since step 5 shows a warning, run this sequence to start Clamd and ensure that `freshclam` notifies the `clamd` daemon:
```zsh
sudo launchctl unload /Library/LaunchDaemons/com.personal.freshclam.plist
sudo rm -f /opt/local/var/log/clamav/freshclam.log.lock
sudo rm -f /opt/local/var/run/clamav/freshclam.pid

# This should be empty
lsof | grep freshclam.log

sudo rm /opt/local/var/log/clamav/freshclam.log
sudo touch /opt/local/var/log/clamav/freshclam.log
sudo chown root:wheel /opt/local/var/log/clamav/freshclam.log
sudo chmod 644 /opt/local/var/log/clamav/freshclam.log

sudo rm -f /opt/local/share/clamav/daily.cvd
sudo freshclam
# Clamd successfully notified about the update.

sudo launchctl load /Library/LaunchDaemons/com.personal.freshclam.plist
```
 11. **Checkpoint** - Verify base installation:
```zsh
# Check daemons are running
sudo launchctl list | grep com.personal
# 1234	0	com.personal.clamd
# -	0	com.personal.freshclam

# Check socket exists with correct permissions (should be srw-rw-rw-)
ls -la /opt/local/var/run/clamav/clamd.socket
# srw-rw-rw-  1 root  wheel  0 Dec 28 17:45 /opt/local/var/run/clamav/clamd.socket

# Check ClamAV version and database (works as any user due to socket permissions)
clamdscan --version
# ClamAV 1.5.1/27863/Sun Dec 28 15:26:03 2025

# Test scan with EICAR
cd ~/Downloads
curl -L -o eicar-test.txt https://secure.eicar.org/eicar.com.txt
clamdscan -i eicar-test.txt
# eicar-test.txt: Eicar-Test-Signature FOUND
rm -f eicar-test.txt
```

**Note** EICAR is a dummy file that only contains a signature that should notify an antivirus. It does not contain anything malicious.

**Note** macOS may show background app notifications from "Joshua Root" when ClamAV services run. This is normal - Joshua Root is the MacPorts developer who signs the packages.

### Part 1-1: Ensuring that Warren also gets his dear permissions
 1. Add MacPorts to warren's PATH (both `.zshrc` and `.zprofile` for interactive and login shells):
```zsh
su - warren
echo 'export PATH="/opt/local/bin:/opt/local/sbin:$PATH"' >> ~/.zshrc
echo 'export PATH="/opt/local/bin:/opt/local/sbin:$PATH"' >> ~/.zprofile
source ~/.zshrc

# Verify
clamdscan --version
exit
```
 2. Test that PATH persists in login shells:
```zsh
su - warren -c "clamdscan --version"
# ClamAV 1.5.1/27871/...
```
 3. Making sure this is in admin's profile, verify FDA is enabled for ClamAVDaemon.app (**Settings > Privacy & Security > Full Disk Access**). If scanning shows "Operation not permitted" errors, ensure ClamAVDaemon.app is added and enabled, then restart clamd:
```zsh
sudo launchctl unload /Library/LaunchDaemons/com.personal.clamd.plist
sudo launchctl load /Library/LaunchDaemons/com.personal.clamd.plist
```
 4. Test scanning as warren:
```zsh
su - warren
cd ~/Downloads
curl -L -o eicar-test.txt https://secure.eicar.org/eicar.com.txt
clamdscan eicar-test.txt
# eicar-test.txt: Eicar-Test-Signature FOUND
rm -f eicar-test.txt
exit
```

### Part 2: Daily Scan Setup (Multi-User)
 1. Create the daily scan script (in this [repo](https://github.com/crimsonpython24/macos-setup/blob/master/clamav-scan.sh)):
```zsh
sudo mkdir -p /usr/local/bin 
sudo vi /usr/local/bin/clamav-scan.sh
```
```zsh
sudo chmod 755 /usr/local/bin/clamav-scan.sh
```
 2. Create a permission wrapper that scans both users (because giving `/bin/bash` FDA is insecure). This wrapper scans both admin and warren directories:
```zsh
sudo mkdir -p /Applications/ClamAVScan.app/Contents/MacOS

sudo tee /Applications/ClamAVScan.app/Contents/MacOS/ClamAVScan << 'EOF'
#!/bin/bash
# Multi-user daily scan - scans both admin and warren
/usr/local/bin/clamav-scan.sh /Users/admin /Users/warren
EOF

sudo chmod +x /Applications/ClamAVScan.app/Contents/MacOS/ClamAVScan
```
```zsh
sudo tee /Applications/ClamAVScan.app/Contents/Info.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>ClamAVScan</string>
    <key>CFBundleIdentifier</key>
    <string>com.personal.clamav-scan</string>
    <key>CFBundleName</key>
    <string>ClamAVScan</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
</dict>
</plist>
EOF
```
 3. Add `/Applications/ClamAVScan.app` to FDA (**Settings > Privacy & Security > Full Disk Access**).
 4. Create LaunchDaemon for daily scans (runs at 4am as root, scans all users):
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
        <string>/Applications/ClamAVScan.app/Contents/MacOS/ClamAVScan</string>
    </array>
    <key>UserName</key>
    <string>root</string>
    <key>GroupName</key>
    <string>wheel</string>
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
 5. If LaunchDaemon times are changed, remember to restart Clamscan.
```
sudo launchctl unload /Library/LaunchDaemons/com.personal.clamscan.plist
sudo launchctl load /Library/LaunchDaemons/com.personal.clamscan.plist
```
 6. **Checkpoint** - Verify daily scan setup (also re-verifies Part 1):
```zsh
# Re-verify daemons from Part 1
sudo launchctl list | grep com.personal
# 1234	0	com.personal.clamd
# -	0	com.personal.freshclam
# -	0	com.personal.clamscan -- there is no PID because it only runs periodically

# Test daily scan manually (creates test files in both user directories)
curl -L -o ~/Downloads/eicar-admin-test.txt https://secure.eicar.org/eicar.com.txt
su - warren -c "curl -L -o ~/Downloads/eicar-warren-test.txt https://secure.eicar.org/eicar.com.txt"

sudo /Applications/ClamAVScan.app/Contents/MacOS/ClamAVScan
# Expected: 
#  - "2 infected file(s) found" message (one from each user)
#  - files moved to /var/root/quarantine/
#  - dialog notification appears
#  - email NOT sent yet (email setup is next)

# Check log was created
sudo tail -30 /var/root/clamav-logs/scan-$(date +%F).log

# Check quarantine has files from both users
sudo ls /var/root/quarantine/
# eicar-admin-test.txt  eicar-warren-test.txt

# Cleanup
sudo bash -c 'rm -rf /var/root/quarantine/*'
```

### Part 3: Email Notifications
> Skip this section if you don't want email alerts. The scan scripts will work fine without email - alerts simply won't be sent.

 1. To generate a Gmail App Password:
   - Go to https://myaccount.google.com/security
   - Enable 2-Step Verification if not already enabled
   - Search for "App passwords"
   - Generate a new app password for "Mail"
   - Use that 16-character password in the file above
 2. Create SASL password file:
```zsh
sudo vi /etc/postfix/sasl_passwd

# Add (replace with your email and app password):
[smtp.gmail.com]:587 yjwarrenwang@gmail.com:YOUR_APP_PASSWORD_HERE
```
 3. Configure postfix and click "Allow" for prompted notification:
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
 6. Transfer log ownerships to `admin` (not `root`):
```zsh
sudo chown -R admin:staff ~/clamav-logs
sudo chown -R admin:staff ~/quarantine 2>/dev/null || mkdir -p ~/quarantine
```
 7. **Checkpoint** - Verify email AND re-verify Parts 1-2:
```zsh
# Test email directly
echo "Test email from ClamAV setup" | mail -s "ClamAV Test" yjwarrenwang@gmail.com
sleep 5
mailq
# Mail queue is empty
# Check inbox for the test email, might need a minute

# Re-verify all daemons
sudo launchctl list | grep com.personal
# 1234	0	com.personal.clamd
# -	0	com.personal.freshclam
# -	0	com.personal.clamscan

# Full integration test with email (both users)
curl -L -o ~/Downloads/eicar-admin-email.txt https://secure.eicar.org/eicar.com.txt
su - warren -c "curl -L -o ~/Downloads/eicar-warren-email.txt https://secure.eicar.org/eicar.com.txt"

sudo /Applications/ClamAVScan.app/Contents/MacOS/ClamAVScan
# Expected:
#   - scan completes finding 2 infected files
#   - dialog notification appears
#   - email IS sent (check inbox)
#   - log shows "Email sent successfully"

sudo tail -20 /var/root/clamav-logs/scan-$(date +%F).log
# Should show "2 infected file(s) found" and "Email sent successfully"

# Cleanup
sudo bash -c 'rm -rf /var/root/quarantine/*'
```

### Part 4: On-Access Scanning (Per-User)
> There is no official on-access scanning on macOS (only Linux via `fanotify`). This uses `fswatch` as a workaround for real-time file monitoring.

> **Multi-User Note:** On-access scanning runs per-user via LaunchAgents. Each user gets their own instance that monitors their own directories.

 1. Install `fswatch`:
```zsh
sudo port install fswatch
```
 2. Create the on-access scan script (also in [this repo](https://github.com/crimsonpython24/macos-setup/blob/master/clamav-onaccess.sh)):
```zsh
sudo vi /usr/local/bin/clamav-onaccess.sh
# ...
```
```zsh
# Make executable by all users
sudo chmod 755 /usr/local/bin/clamav-onaccess.sh
```
 3. Create the on-access wrapper app with FDA (shared by all users):
```zsh
sudo mkdir -p /Applications/ClamAVOnAccess.app/Contents/MacOS

sudo tee /Applications/ClamAVOnAccess.app/Contents/MacOS/ClamAVOnAccess << 'EOF'
#!/bin/bash
exec /usr/local/bin/clamav-onaccess.sh "$@"
EOF

sudo chmod +x /Applications/ClamAVOnAccess.app/Contents/MacOS/ClamAVOnAccess
```
```zsh
sudo tee /Applications/ClamAVOnAccess.app/Contents/Info.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>ClamAVOnAccess</string>
    <key>CFBundleIdentifier</key>
    <string>com.personal.clamav-onaccess</string>
    <key>CFBundleName</key>
    <string>ClamAVOnAccess</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
</dict>
</plist>
EOF
```
 4. Add `/Applications/ClamAVOnAccess.app` to FDA (**Settings > Privacy & Security > Full Disk Access**).
 5. Create LaunchAgent for admin user (runs as admin, monitors admin's directories):
```zsh
# Run as admin user (not sudo)
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
        <string>/Applications/ClamAVOnAccess.app/Contents/MacOS/ClamAVOnAccess</string>
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
```zsh
# Load for admin user
launchctl load ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist
```
 6. Create LaunchAgent for warren user (runs as warren, monitors warren's directories):
```zsh
# Switch to warren or run these commands as warren
su - warren

# Create LaunchAgents directory
mkdir -p ~/Library/LaunchAgents

# Create the plist (same content, but runs in warren's context)
cat > ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.personal.clamav-onaccess</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/ClamAVOnAccess.app/Contents/MacOS/ClamAVOnAccess</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/clamav-onaccess-warren-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/clamav-onaccess-warren-stderr.log</string>
</dict>
</plist>
EOF

# Load for warren user
launchctl load ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist

# Exit back to admin
exit
```
 7. **Checkpoint** - Full system verification (verifies everything):
```zsh
# Verify all system daemons (as admin with sudo)
sudo launchctl list | grep com.personal
# 1234	0	com.personal.clamd
# -	0	com.personal.freshclam
# -	0	com.personal.clamscan

# Verify admin's on-access agent
launchctl list | grep clamav-onaccess
# 1825	0	com.personal.clamav-onaccess

# Verify warren's on-access agent
su - warren -c "launchctl list | grep clamav-onaccess"
# 1830	0	com.personal.clamav-onaccess

# Check fswatch is running for both users
ps aux | grep fswatch | grep -v grep
# admin  ... /opt/local/bin/fswatch -0 -r -l 2...
# warren ... /opt/local/bin/fswatch -0 -r -l 2...

# Verify clamd socket (should be accessible by all users)
ls -la /opt/local/var/run/clamav/clamd.socket
# srw-rw-rw-  1 root  wheel  0 Dec 28 17:45 /opt/local/var/run/clamav/clamd.socket

# Test on-access scanning for admin
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
#   - notification appears
#   - dialog "ClamAV On-Access Alert"
#   - email received
rm -rf ~/quarantine/*

# Test on-access scanning for warren as admin
su - warren
/Applications/ClamAVOnAccess.app/Contents/MacOS/ClamAVOnAccess &
# [1] 5084

ps aux | grep fswatch | grep warren
# warren            5104   0.0  0.0 410604496   5568 s001  SN    6:20PM   0:00.00 /opt/local/bin/fswatch -0 -r -l 2...

cd ~/Downloads
curl -L -o eicar-warren-test.txt https://secure.eicar.org/eicar.com.txt
# There will be an error because GUI cannot be accessed, but an email should be sent.
```
```zsh
# Log into warren
# Terminal 1 (as warren):
tail -f ~/clamav-logs/onaccess-$(date +%F).log

# Terminal 2 (as warren):
cd ~/Downloads
curl -L -o eicar-warren-test.txt https://secure.eicar.org/eicar.com.txt
# Expected: same alerts as admin, but in warren's context
rm -rf ~/quarantine/*
exit

# Test clean files (should not alert)
echo "normal content" > ~/Downloads/clean-test.txt
# Expected in log: "Clean" (or skipped if < 50 bytes)

# Verify email queue is clear
mailq
# "Mail queue is empty"

# Check logs exist for both users
ls -la ~/clamav-logs/
ls -la /Users/warren/clamav-logs/
# Expected: scan-YYYY-MM-DD.log and onaccess-YYYY-MM-DD.log in each
```

**Note** If testing for daily scan at this step, make sure that all on-access processes are killed, across all users:
```zsh
ps aux | grep fswatch | grep -v grep
sudo kill -9 <PID>
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

### Ref: Restart Commands
If something is not working, restart the relevant service:
```zsh
# System daemons (run as admin with sudo)
sudo launchctl unload /Library/LaunchDaemons/com.personal.clamd.plist
sudo launchctl load /Library/LaunchDaemons/com.personal.clamd.plist

sudo launchctl unload /Library/LaunchDaemons/com.personal.freshclam.plist
sudo launchctl load /Library/LaunchDaemons/com.personal.freshclam.plist

sudo launchctl unload /Library/LaunchDaemons/com.personal.clamscan.plist
sudo launchctl load /Library/LaunchDaemons/com.personal.clamscan.plist

# Trigger daily scan manually
sudo launchctl start com.personal.clamscan

# On-access for admin (run as admin, no sudo)
launchctl unload ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist
launchctl load ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist

# On-access for warren (run as warren, no sudo)
su - warren
launchctl unload ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist
launchctl load ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist
exit
```

### Ref: Log Locations
```zsh
# Daily scan (runs as root)
/var/root/clamav-logs/scan-$(date +%F).log

# On-access for admin
~/clamav-logs/onaccess-$(date +%F).log

# On-access for warren
/Users/warren/clamav-logs/onaccess-$(date +%F).log

# ClamAV daemon
/opt/local/var/log/clamav/clamd.log

# Freshclam
/opt/local/var/log/clamav/freshclam.log

# Quarantine locations
/var/root/quarantine/           # Daily scan quarantine
~/quarantine/                   # Admin on-access quarantine
/Users/warren/quarantine/       # Warren on-access quarantine
```

### Ref: Multi-User Architecture Summary

| Component | Type | Runs As | Scope | FDA Required |
|-----------|------|---------|-------|--------------|
| clamd | LaunchDaemon | root | System-wide | Yes (ClamAVDaemon.app) |
| freshclam | LaunchDaemon | root | System-wide | No |
| Daily scan | LaunchDaemon | root | Scans all users | Yes (ClamAVScan.app) |
| On-access (admin) | LaunchAgent | admin | admin's files | Yes (ClamAVOnAccess.app) |
| On-access (warren) | LaunchAgent | warren | warren's files | Yes (ClamAVOnAccess.app) |

<sup>https://paulrbts.github.io/blog/software/2017/08/18/clamav/</sup><br/>
<sup>https://blog.csdn.net/qq_60735796/article/details/156052196</sup>

## 3. Santa Setup
 1. Install the updated release from Northpole on [GitHub](https://northpole.dev/deployment/install-package/#releases)
 2. Grant permissions:
    - "Login Items & Extensions" > "App Background Activity" add Santa.app
    - "Login Items & Extensions" > "Extensions" > "By Category" > "Endpoint Security Extensions" add Santa daemon
    - "Login Items & Extensions" > "Extensions" > "By App" > should show "Santa" after restarting Settings
    - "Privacy" > "Full Disk Access" enable Santa Endpoint Security Extension (close and re-open Settings app after Santa install)
 3. Check if Santa is running:
```zsh
sudo santactl doctor
```
 4. Download the [Configuration Profile](https://github.com/crimsonpython24/macos-setup/blob/master/santa.mobileconfig). If the NIST configuration profile blocks installation, remove that profile first, install this Santa profile, and then add the original MDM back.
```zsh
vi santa.mobileconfig
# ...
sudo open santa.mobileconfig
```
 5. Blocking application example (a selected list of banned apps are [in the repo](https://github.com/crimsonpython24/macos-setup/blob/master/santa_base.json)):
```zsh
santactl fileinfo /System/Applications/Dictionary.app 
Path                   : /System/Applications/Dictionary.app/Contents/MacOS/Dictionary
SHA-256                : 85f755c92afe93a52034d498912be0ab475020d615bcbe2ac024babbeed4439f
SHA-1                  : 0cb8cb1f8d31650f4d770d633aacce9b2fcc5901
Bundle Name            : Dictionary
Bundle Version         : 294
Bundle Version Str     : 2.3.0
Signing ID             : platform:com.apple.Dictionary

# Better approach: use signing ID (will not change even with app update)
sudo santactl rule \
  --block \
  --signingid \
  --identifier platform:com.apple.Dictionary
```
```zsh
sudo santactl rule --block --sha256 85f755c92afe93a52034d498912be0ab475020d615bcbe2ac024babbeed4439f 
# Added rule for SHA-256: 85f755c92afe93a52034d498912be0ab475020d615bcbe2ac024babbeed4439f

sudo santactl rule --remove --sha256 85f755c92afe93a52034d498912be0ab475020d615bcbe2ac024babbeed4439f
# Removed rule for SHA-256: 85f755c92afe93a52034d498912be0ab475020d615bcbe2ac024babbeed4439f.
```
 6. When importing/exporting rules, use:
```zsh
sudo santactl rule --export santa1.json
```

## 4. DNS Stuffs
### A) Hosts File
 - Append [StevenBlack/hosts](https://github.com/StevenBlack/hosts) into `hosts`; this step can also be done in Little Snitch.
```zsh
curl https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | sudo tee -a /etc/hosts
```

### B) DNSCrypt
> Some VPN applications override DNS settings on connect; may need to reconfigure VPN after setting up a local DNS server (change DNS to 127.0.0.1).
> No need to configure DNSSEC in this step; it will be handled with Unbound.

 1. Install DNSCrypt with `sudo port install dnscrypt-proxy` and load it on startup with `sudo port load dnscrypt-proxy`. Update DNS server settings to point to 127.0.0.1 (Settings > "Network" > Wi-Fi or Eth > Current network "Details" > DNS tab).
 2. Because there will be no connection until section 3(C) is configured, first install Unbound with `sudo port install unbound` and let it run at startup with `sudo port load unbound`.
 3. Find DNSCrypt's installation location with `port contents dnscrypt-proxy` to get the configuration path (e.g., `/opt/local/share/dnscrypt-proxy/example.toml`).
 4. Edit the file and change listening ports:
```zsh
sudo vi /opt/local/share/dnscrypt-proxy/dnscrypt-proxy.toml
```
```toml
# /opt/local/share/dnscrypt-proxy/dnscrypt-proxy.toml

# listener config
listen_addresses = ['127.0.0.1:54', '[::1]:54']

# server selection
ipv4_servers = true
ipv6_servers = false
dnscrypt_servers = true
doh_servers = false
odoh_servers = false

# server requirements
require_dnssec = true
require_nolog = true
require_nofilter = true

# load balancing server selection
lb_strategy = 'p2'
lb_estimator = true

# disable resolvers whose operators also run anonymizing relays
# prevents same operator from seeing both relay and resolver traffic
disabled_server_names = [
    'cs-de', 'cs-nl', 'cs-fr', 'cs-austria', 'cs-barcelona',
    'scaleway-fr', 'scaleway-ams',
    'dnscrypt.uk-ipv4', 'dnscrypt.uk-ipv6', 'v.dnscrypt.uk-ipv4', 'v.dnscrypt.uk-ipv6'
]

# connection settings
force_tcp = false
timeout = 5000
keepalive = 30
cert_refresh_delay = 240
cert_ignore_timestamp = false

# privacy hardening
dnscrypt_ephemeral_keys = true
tls_disable_session_tickets = true

# fallbacks
bootstrap_resolvers = ['9.9.9.9:53', '1.1.1.1:53']
ignore_system_dns = true
netprobe_timeout = 60
netprobe_address = '9.9.9.9:53'

# query filtering
block_ipv6 = false
block_unqualified = true
block_undelegated = true
reject_ttl = 10

# cache
cache = true
cache_size = 4096
cache_min_ttl = 2400
cache_max_ttl = 86400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 600

# resolver sources (replace existing config)
[sources.public-resolvers]
urls = [
    'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md',
    'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md',
]
cache_file = 'public-resolvers.md'
minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
refresh_delay = 73
prefix = ''

[sources.relays]
urls = [
    'https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md',
    'https://download.dnscrypt.info/resolvers-list/v3/relays.md',
]
cache_file = 'relays.md'
minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
refresh_delay = 73
prefix = ''

# anonymized dns (relay thru 3p servers)
[anonymized_dns]
routes = [
    { server_name='*', via=[
        'anon-cs-de',
        'anon-cs-nl', 
        'anon-cs-fr',
        'anon-scaleway-ams',
        'anon-kama',
        'anon-ibksturm',
        'anon-meganerd',
        'anon-inconnu'
    ]}
]
skip_incompatible = true
direct_cert_fallback = false
```
```zsh
sudo port unload dnscrypt-proxy
sudo port load dnscrypt-proxy
```
 4. Check if current configuration is valid (will not run otherwise):
```zsh
sudo /opt/local/sbin/dnscrypt-proxy -config /opt/local/share/dnscrypt-proxy/dnscrypt-proxy.toml -check
# Remember to reload dnscrypt-proxy after toml change

# Run in foreground with verbose logging
sudo /opt/local/sbin/dnscrypt-proxy -config /opt/local/share/dnscrypt-proxy/dnscrypt-proxy.toml -loglevel 0
```
```zsh
sudo lsof +c 15 -Pni UDP:54
# dnscrypt-proxy 57409 root    7u  IPv4 0xf2ce17b711151ccc      0t0  UDP 127.0.0.1:54
# dnscrypt-proxy 57409 root    9u  IPv6 0x8031285518513383      0t0  UDP [::1]:54
```
 5. After changing the network DNS resolver to use local, ensure that Wi-Fi interfaces use `127.0.0.1` instead of `192.168.x.x`:
```zsh
# Sometimes system will not respect GUI settings
sudo networksetup -setdnsservers "Wi-Fi" 127.0.0.1

networksetup -getdnsservers "Wi-Fi"
# 127.0.0.1

scutil --dns | head -10
# nameserver[1] : 127.0.0.1

sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
```
 6. Again, since this guide routes `dnscrypt-proxy` to port 54, there still will not be Internet connection until after section 4(C)

### C) Unbound
> The original guide uses `dnsmasq`; however, Dnsmasq will not reload `ad` (authenticated data) in DNS queries if an entry is cached. Hence this section is replaced with unbound to achieve both caching and auth.

 1. Unbound should already be installed in 4(B). If not, set DNS back to 192.168.0.1, install Unbound, and then change back to 127.0.0.1.
 2. Create directories and configurations.
```zsh
sudo mkdir -p /opt/local/etc/unbound
port contents unbound | grep unbound.conf
sudo vi /opt/local/etc/unbound/unbound.conf
```
```conf
# /opt/local/etc/unbound/unbound.conf

server:
    # listener config
    interface: 127.0.0.1
    interface: ::1
    port: 53
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    
    # bind to specific interfaces only
    interface-automatic: no
    
    # access control
    access-control: 127.0.0.0/8 allow
    access-control: ::1 allow
    access-control: 0.0.0.0/0 refuse
    access-control: ::0/0 refuse
    
    # cache settings
    cache-min-ttl: 2400
    cache-max-ttl: 86400
    cache-max-negative-ttl: 3600
    
    # serve expired entries while refreshing (resilience)
    serve-expired: yes
    serve-expired-ttl: 86400
    serve-expired-reply-ttl: 30
    serve-expired-client-timeout: 1800
    
    # cache sizes (slightly increased from original)
    msg-cache-size: 64m
    rrset-cache-size: 128m
    neg-cache-size: 16m
    
    # DNSSEC
    module-config: "validator iterator"
    auto-trust-anchor-file: "/opt/local/etc/unbound/root.key"
    val-clean-additional: yes
    val-permissive-mode: no
    val-log-level: 1
    
    # trust anchor signaling (RFC 8145)
    trust-anchor-signaling: yes
    
    # root key sentinel (detects root key rollovers)
    root-key-sentinel: yes
    
    # dns rebinding protection
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: fd00::/8
    private-address: fe80::/10
    private-address: 127.0.0.0/8
    private-address: ::1/128

    # block IPv4-mapped IPv6 addresses (bypass prevention)
    private-address: ::ffff:0:0/96
    
    # allow localhost queries (rebind-localhost-ok equivalent)
    private-domain: "localhost."
    private-domain: "127.in-addr.arpa."
    
    # DNSSEC hardening
    harden-algo-downgrade: yes
    harden-below-nxdomain: yes
    harden-dnssec-stripped: yes
    harden-glue: yes
    harden-large-queries: yes
    harden-referral-path: no  # Changed: experimental, can cause performance issues
    harden-short-bufsize: yes
    harden-unknown-additional: yes  # NEW: reject unknown record types in additional section
    
    # 0x20-encoded random bits to foil spoof attempts
    use-caps-for-id: yes
    
    # deny queries of type ANY (reduces amplification attacks)
    deny-any: yes
    
    # unwanted reply threshold: defend against cache poisoning
    # clears cache if threshold reached (10 million suggested by manpage)
    unwanted-reply-threshold: 10000000
    
    # EDNS buffer size (DNS Flag Day 2020)
    edns-buffer-size: 1232
    max-udp-size: 1232
    
    # outbound port range w/ source port randomization
    outgoing-port-permit: 1024-65535
    outgoing-port-avoid: 0-1023
    
    # do not query localhost
    do-not-query-localhost: no
    
    # privacy features
    qname-minimisation: yes
    qname-minimisation-strict: no
    aggressive-nsec: yes
    hide-identity: yes
    hide-version: yes
    hide-trustanchor: yes 
    identity: "DNS"  
    minimal-responses: yes
    
    # performance?
    num-threads: 2
    
    # slabs should be power of 2 close to num-threads
    msg-cache-slabs: 4
    rrset-cache-slabs: 4
    infra-cache-slabs: 4
    key-cache-slabs: 4
    
    # socket options (increase send/recv buffer)
    so-reuseport: yes
    so-rcvbuf: 4m  
    so-sndbuf: 4m  
    
    # prefetch popular items before they expire
    prefetch: yes
    prefetch-key: yes
    
    # rotate RRset order in responses (load balancing)
    rrset-roundrobin: yes
    
    # number of queries per thread
    num-queries-per-thread: 4096
    outgoing-range: 8192
    
    # TCP connection handling
    incoming-num-tcp: 100
    outgoing-num-tcp: 100
    
    # extra delay for timeouted udp ports (prevents port counter issues)
    delay-close: 10000
    
    # infra-cache settings
    infra-cache-numhosts: 10000
    infra-keep-probing: yes  # NEW: keep probing hosts that are down
    
    # local zones for tld blocking
    local-zone: "local." static
    local-zone: "localhost." static
    local-zone: "home." static
    local-zone: "lan." static
    local-zone: "internal." static
    local-zone: "corp." static
    local-zone: "private." static
    local-zone: "test." static
    local-zone: "invalid." static
    
    # additional rfc recommended zones
    local-zone: "onion." static
    local-zone: "home.arpa." static
    
    # bogus private reverse lookups (bogus-priv equivalent)
    local-zone: "10.in-addr.arpa." static
    local-zone: "16.172.in-addr.arpa." static
    local-zone: "17.172.in-addr.arpa." static
    local-zone: "18.172.in-addr.arpa." static
    local-zone: "19.172.in-addr.arpa." static
    local-zone: "20.172.in-addr.arpa." static
    local-zone: "21.172.in-addr.arpa." static
    local-zone: "22.172.in-addr.arpa." static
    local-zone: "23.172.in-addr.arpa." static
    local-zone: "24.172.in-addr.arpa." static
    local-zone: "25.172.in-addr.arpa." static
    local-zone: "26.172.in-addr.arpa." static
    local-zone: "27.172.in-addr.arpa." static
    local-zone: "28.172.in-addr.arpa." static
    local-zone: "29.172.in-addr.arpa." static
    local-zone: "30.172.in-addr.arpa." static
    local-zone: "31.172.in-addr.arpa." static
    local-zone: "168.192.in-addr.arpa." static
    
    # additional private reverse zones
    local-zone: "254.169.in-addr.arpa." static
    local-zone: "d.f.ip6.arpa." static
    local-zone: "8.e.f.ip6.arpa." static
    local-zone: "9.e.f.ip6.arpa." static
    local-zone: "a.e.f.ip6.arpa." static
    local-zone: "b.e.f.ip6.arpa." static
    
    # logging
    verbosity: 1
    use-syslog: yes
    log-queries: no
    log-replies: no
    log-servfail: yes  # NEW: log why queries return SERVFAIL
    log-local-actions: no
    
    # dns error codes
    ede: yes
    ede-serve-expired: yes

# forwarding zones for dnscrypt-proxy (configured upstream)
forward-zone:
    name: "."
    forward-addr: 127.0.0.1@54
    forward-addr: ::1@54
    forward-first: no

# disable remote control
remote-control:
    control-enable: no
```
 3. Initialize root trust anchor for DNSSEC.
```zsh
sudo unbound-anchor -a /opt/local/etc/unbound/root.key
```
 4. Check configurations:
```zsh
sudo unbound-checkconf /opt/local/etc/unbound/unbound.conf
sudo port load unbound
sudo lsof +c 15 -Pni UDP:53
# Should show unbound on 127.0.0.1:53 and [::1]:53
```
 5. Test Unbound dnssec:
```zsh
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder

# First query - should have 'ad' flag
dig @127.0.0.1 dnssec.works

# Second query (cached) - should STILL have 'ad' flag
dig @127.0.0.1 dnssec.works

# Third query - 'ad' flag should persist
dig @127.0.0.1 dnssec.works

# Test DNSSEC validation - this should FAIL
dig @127.0.0.1 fail01.dnssec.works
```
```zsh
unbound-host -vDr test.dnscheck.tools
test.dnscheck.tools has address xx.xx.xx.xx (secure)
test.dnscheck.tools has IPv6 address xx:xx:xx:xx:xx:xx (secure)
test.dnscheck.tools mail is handled by 0 . (secure)

unbound-host -vDr badsig.test.dnscheck.tools
# ... (BOGUS (security failure))
```

**Note** Some websites will not have `ad` flag no matter how hard one tries. E.g.,
```zsh
dig DNSKEY archlinux.org
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 38272
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; QUESTION SECTION:
;archlinux.org.			IN	DNSKEY    <--- empty!

;; AUTHORITY SECTION:
archlinux.org.		3600	IN	SOA	hydrogen.ns.hetzner.com. dns.hetzner.com. 2026010201 86400 10800 3600000 3600
```
```zsh
dig DNSKEY dnssec.works
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 65193
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;dnssec.works.			IN	DNSKEY

;; ANSWER SECTION:
dnssec.works.		4965	IN	DNSKEY	257 3 8 AwEAAa+YwrBlCwfJzwmsSK87hKFAm+yz0...
```

**Note** Debugging commands:
```zsh
log show --predicate 'process == "dnscrypt-proxy"' --last 5m
curl -I https://google.com

# Test if resolver is blocking domains itself
dig @127.0.0.1 dnsleaktest.com
dig @9.9.9.9 dnsleaktest.com
```
One might have to quit and restart Safari (while testing) with `killall Safari`.

<sup>https://wiki.archlinux.org/title/Dnscrypt-proxy#Startup</sup></br>
<sup>https://00f.net/2019/11/03/stop-using-low-dns-ttls/</sup></br>
<sup>https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html</sup>
<sup>https://wiki.archlinux.org/title/Unbound</sup>
