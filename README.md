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

> **Multi-User Setup:** This guide configures ClamAV for two users: `admin` (administrator) and `warren` (daily use). System daemons run under admin, while on-access scanning runs per-user.

1. Install ClamAV from MacPorts: `sudo port install clamav-server`. This ClamAV port creates all non-example configurations already. *Important* do NOT execute `sudo port load clamav-server` because doing so will conflict with this guide's startup scripts; also do not give `daemondo` full-disk access because it is unnecessary.

2. Give the current user database and logfile permissions:
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

3. Create directories for both users:
```zsh
# Admin user
mkdir -p /Users/admin/clamav-logs /Users/admin/quarantine

# Warren user
sudo mkdir -p /Users/warren/clamav-logs /Users/warren/quarantine
sudo chown warren:staff /Users/warren/clamav-logs /Users/warren/quarantine
```

4. Set up Freshclam:
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

5. Set up `clamd`:
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
ExcludePath ^/usr/
```

6. Run `freshclam` *without sudo* to download the initial virus database (this may take a while). If it shows `WARNING: Clamd was NOT notified: Can't connect to clamd through /opt/local/var/run/clamav/clamd.socket: No such file or directory`, keep proceeding until step 9.
```zsh
freshclam
```

7. Create clamd daemon:
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

8. Create freshclam daemon (for automatic database updates):
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

9. If step 6 shows a warning, run this sequence to start Clamd and ensure that freshclam notifies the clamd daemon:
```zsh
sudo launchctl unload /Library/LaunchDaemons/com.personal.freshclam.plist
rm -f /opt/local/var/log/clamav/freshclam.log.lock
rm -f /opt/local/var/run/clamav/freshclam.pid

# This should be empty
lsof | grep freshclam.log

rm /opt/local/var/log/clamav/freshclam.log
touch /opt/local/var/log/clamav/freshclam.log
sudo chown admin:staff /opt/local/var/log/clamav/freshclam.log
sudo chmod 644 /opt/local/var/log/clamav/freshclam.log

rm /opt/local/share/clamav/daily.cvd
freshclam
# Clamd successfully notified about the update.

sudo launchctl load /Library/LaunchDaemons/com.personal.freshclam.plist
```

10. **Checkpoint** - Verify base installation:
```zsh
# Check daemons are running
sudo launchctl list | grep com.personal
# 1234	0	com.personal.clamd
# 1340	0	com.personal.freshclam

# Check socket exists
ls -la /opt/local/var/run/clamav/clamd.socket
# srw-rw-rw-  1 admin  staff  0 Dec 28 17:45 /opt/local/var/run/clamav/clamd.socket

# Check ClamAV version and database
clamdscan --version
# ClamAV 1.5.1/27863/Sun Dec 28 15:26:03 2025

# Test scan with EICAR
cd ~/Downloads
curl -L -o eicar-test.txt https://secure.eicar.org/eicar.com.txt
clamdscan -i eicar-test.txt
# Expected: eicar-test.txt: Eicar-Test-Signature FOUND
rm -f eicar-test.txt
```

**Note** EICAR is a dummy "virus" file that contains a signature that should notify antivirus software. It does not contain anything malicious.

**Note** macOS may show background app notifications from "Joshua Root" when ClamAV services run. This is normal - Joshua Root is the MacPorts developer who signs the packages.

---

### Part 2: Daily Scan Setup

1. Create the daily scan script (see `clamav-scan.sh` in this repo):
```zsh
sudo mkdir -p /usr/local/bin 
sudo vi /usr/local/bin/clamav-scan.sh
sudo chmod +x /usr/local/bin/clamav-scan.sh
```

2. Create a permission wrapper that scans both users (because giving `/bin/bash` FDA is insecure):
```zsh
sudo vi /usr/local/bin/clamav-wrapper.c
```
```c
#include <unistd.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    char *args[] = {"/bin/bash", "/usr/local/bin/clamav-scan.sh", 
                    "/Users/admin", "/Users/warren", NULL};
    execv("/bin/bash", args);
    perror("execv failed");
    return 1;
}
```
```zsh
sudo gcc -o /usr/local/bin/clamav-wrapper /usr/local/bin/clamav-wrapper.c
sudo chmod +x /usr/local/bin/clamav-wrapper
```

3. Give wrapper permissions to run full-disk scans (secure because this script is only manually triggered):
```zsh
sudo mkdir -p /Applications/ClamAVScan.app/Contents/MacOS

sudo tee /Applications/ClamAVScan.app/Contents/MacOS/ClamAVScan << 'EOF'
#!/bin/bash
/usr/local/bin/clamav-scan.sh /Users/admin /Users/warren
EOF

sudo chmod +x /Applications/ClamAVScan.app/Contents/MacOS/ClamAVScan

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

4. Add `/Applications/ClamAVScan.app` to FDA (**Settings > Privacy & Security > Full Disk Access**)

5. Create LaunchDaemon for daily scans (runs at 4am):
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

6. **Checkpoint** - Verify daily scan setup (also re-verifies Part 1):
```zsh
# Re-verify daemons from Part 1
sudo launchctl list | grep com.personal
# 1234	0	com.personal.clamd
# 1515	0	com.personal.freshclam
# -	0	com.personal.clamscan -- there is no PID because it only runs periodically

# Test daily scan manually (scans both users)
curl -L -o ~/Downloads/eicar-daily-test.txt https://secure.eicar.org/eicar.com.txt
/usr/local/bin/clamav-scan.sh ~/Downloads
# Expected: 
#   - Scan output with statistics
#   - "1 infected file(s) found" message
#   - File moved to ~/quarantine/
#   - Dialog notification appears
#   - Email NOT sent yet (email setup is next)

# Check log was created
tail -20 ~/clamav-logs/scan-$(date +%F).log
# ----------- SCAN SUMMARY -----------
# Known viruses: 3701067
# Engine version: 1.5.1
# Scanned directories: 1
# Scanned files: 2
# Infected files: 1

# Check quarantine
ls ~/quarantine/
# eicar-daily-test.txt
```

---

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
# Mail queue is empty
# Check inbox for the test email, might need a minute

# Re-verify all daemons
sudo launchctl list | grep com.personal
# 1234	0	com.personal.clamd
# 1730	0	com.personal.freshclam
# -	0	com.personal.clamscan

# Full integration test with email
curl -L -o ~/Downloads/eicar-email-test.txt https://secure.eicar.org/eicar.com.txt
/usr/local/bin/clamav-scan.sh ~/Downloads
# Expected:
#   - Scan completes
#   - Dialog notification appears
#   - Email IS sent this time (check inbox)
#   - Log shows "Email sent successfully"

tail -10 ~/clamav-logs/scan-$(date +%F).log
# "Email sent successfully" somewhere
```

---

### Part 4: On-Access Scanning (Optional)

> There is no official on-access scanning on macOS (only Linux via `fanotify`). This uses `fswatch` as a workaround for real-time file monitoring.

> **Per-User Setup:** On-access scanning runs as a LaunchAgent (per-user), not a system daemon. Each user needs their own LaunchAgent.

1. Install `fswatch`:
```zsh
sudo port install fswatch
```

2. Create the on-access scan script (see `clamav-onaccess.sh` in this repo):
```zsh
sudo vi /usr/local/bin/clamav-onaccess.sh
sudo chmod +x /usr/local/bin/clamav-onaccess.sh
```

3. **For admin user** - Create LaunchAgent (runs as user, not system, so do not use sudo):
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
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
    <key>StandardOutPath</key>
    <string>/tmp/clamav-onaccess-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/clamav-onaccess-stderr.log</string>
</dict>
</plist>
```

4. Load the admin LaunchAgent:
```zsh
launchctl load ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist
```

5. **For warren user** - Set up on-access scanning (run these as admin):
```zsh
# Create LaunchAgents directory for warren
sudo mkdir -p /Users/warren/Library/LaunchAgents

# Copy the plist
sudo cp /Users/admin/Library/LaunchAgents/com.personal.clamav-onaccess.plist \
        /Users/warren/Library/LaunchAgents/com.personal.clamav-onaccess.plist

# Fix ownership
sudo chown warren:staff /Users/warren/Library/LaunchAgents/com.personal.clamav-onaccess.plist
```

6. **Login as warren** and load the LaunchAgent:
```zsh
# Run this while logged in as warren
launchctl load ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist
```

7. **Checkpoint** - Full system verification (verifies everything):
```zsh
# === Verify all system daemons (from admin) ===
sudo launchctl list | grep com.personal
# 1234	0	com.personal.clamd
# -	0	com.personal.freshclam
# -	0	com.personal.clamscan

# === Verify on-access for current user ===
launchctl list | grep clamav-onaccess
# 1825	0	com.personal.clamav-onaccess

ps aux | grep fswatch | grep -v grep
# /opt/local/bin/fswatch should be somewhere

# === Verify clamd socket ===
ls -la /opt/local/var/run/clamav/clamd.socket
# srw-rw-rw-  1 admin  staff  0 Dec 28 17:45 /opt/local/var/run/clamav/clamd.socket

# === Test on-access scanning ===
# Terminal 1:
tail -f ~/clamav-logs/onaccess-$(date +%F).log

# Terminal 2:
cd ~/Downloads
curl -L -o eicar-onaccess-test.txt https://secure.eicar.org/eicar.com.txt
# Expected in Terminal 1:
#   - "Scanning: .../eicar-onaccess-test.txt"
#   - "INFECTED: ..."
#   - "Moved to: ~/quarantine"
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

# === Check quarantine ===
ls ~/quarantine/
# Expected: eicar-onaccess-test.txt
```

8. Test with clean file:
```zsh
echo "This is a normal file" > ~/Downloads/clean-file-test.txt
tail -5 ~/clamav-logs/onaccess-$(date +%F).log
# Expected: Shows "Clean" for clean-file-test.txt
```

### Part 5: Log Rotation

1. Create newsyslog configuration for ClamAV:
```zsh
sudo tee /etc/newsyslog.d/clamav.conf << 'EOF'
# ClamAV log rotation - rotate weekly, keep 7 days
/opt/local/var/log/clamav/clamd.log          644  7     *    @T00  J     /opt/local/var/run/clamav/clamd.pid
/opt/local/var/log/clamav/freshclam.log      644  7     *    @T00  J
/Users/admin/clamav-logs/*.log               644  7     *    @T00  J
/Users/warren/clamav-logs/*.log              644  7     *    @T00  J
EOF
```

2. The system will automatically rotate logs. To manually trigger:
```zsh
sudo newsyslog -v
```

3. Add cleanup to the daily scan script by appending before the exit (or create a separate cron):
```zsh
# Add to clamav-scan.sh or run manually
find ~/clamav-logs -name "*.log" -mtime +7 -delete
find ~/quarantine -mtime +30 -delete
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
sudo launchctl unload /Library/LaunchDaemons/com.personal.clamd.plist
sudo launchctl load /Library/LaunchDaemons/com.personal.clamd.plist

sudo launchctl unload /Library/LaunchDaemons/com.personal.freshclam.plist
sudo launchctl load /Library/LaunchDaemons/com.personal.freshclam.plist

sudo launchctl unload /Library/LaunchDaemons/com.personal.clamscan.plist
sudo launchctl load /Library/LaunchDaemons/com.personal.clamscan.plist

# On-access (run as the user, not sudo)
launchctl unload ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist
launchctl load ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist

# Trigger daily scan manually
sudo launchctl start com.personal.clamscan
```

### Ref: Log Locations
```zsh
# Daily scan (per-user, based on who runs it)
~/clamav-logs/scan-$(date +%F).log

# On-access (per-user)
~/clamav-logs/onaccess-$(date +%F).log

# ClamAV daemon
/opt/local/var/log/clamav/clamd.log

# Freshclam
/opt/local/var/log/clamav/freshclam.log
```

### Ref: Multi-User Summary

| Component | Location | Runs as | Covers |
|-----------|----------|---------|--------|
| clamd | /Library/LaunchDaemons/ | admin | System-wide |
| freshclam | /Library/LaunchDaemons/ | admin | System-wide |
| daily scan | /Library/LaunchDaemons/ | admin | Both admin & warren |
| on-access | ~/Library/LaunchAgents/ | Each user | That user only |
| Scripts | /usr/local/bin/ | - | All users |
| Logs | ~/clamav-logs/ | - | Per-user |
| Quarantine | ~/quarantine/ | - | Per-user |

<sup>https://paulrbts.github.io/blog/software/2017/08/18/clamav/</sup><br/>
<sup>https://blog.csdn.net/qq_60735796/article/details/156052196</sup>

## 3. Santa Setup
 1. Install the updated release from Northpole on [GitHub](https://northpole.dev/deployment/install-package/#releases)
 2. Grant permissions:
    - "Login Items & Extensions" > "App Background Activity" add Santa.app
    - "Login Items & Extensions" > "Extensions" > "By Category" > "Endpoint Security Extensions" add Santa daemon
    - "Login Items & Extensions" > "Extensions" > "By App" > should show "Santa" after restarting Settings
    - "Privacy" > "Full Disk Access" enable Santa Security Extensions (will not show up until after restart)
 3. Check if Santa is running:
```zsh
sudo santactl doctor
```
 4. Download the [Configuration Profile](https://github.com/crimsonpython24/macos-setup/blob/master/santa.mobileconfig). If the NIST configuration profile blocks installation, remove that profile first, install this Santa profile, and then add the original MDM back.
 5. Install the Santa configuration profile:
```zsh
sudo open santa.mobileconfig
```
 6. **Important for Lockdown mode**: Before the profile takes effect, allowlist critical binaries:
```zsh
# Export current state as baseline
sudo santactl rule --export ~/santa-pre-lockdown.json

# Allowlist your shell and common tools by Team ID (survives updates)
santactl fileinfo /bin/zsh | grep "Team ID"

# Allowlist all binaries from Apple
sudo santactl rule --allow --teamid APPL

# Allowlist MacPorts binaries (check the signing info first)
santactl fileinfo /opt/local/bin/bash
sudo santactl rule --allow --certificate --sha256 <cert-sha256-from-above>
```

 7. Verify Santa is in Lockdown mode:
```zsh
santactl status | grep "Client Mode"
# Client Mode                    | Lockdown
```

 8. Handling blocked applications:
```zsh
# Check what was blocked recently
log show --predicate 'subsystem == "com.northpolesec.santa"' --last 1h | grep DENY

# Allowlist by signing ID (preferred - survives updates)
sudo santactl rule \
  --allow \
  --signingid \
  --identifier platform:com.apple.TextEdit
```

 9. USB behavior with current config:
    - USB storage devices mount as **read-only** with **noexec**
    - You can read files but cannot execute anything from USB
    - To temporarily allow: remove the profile, use USB, reinstall profile

## 4. DNS Stuffs
### A) Hosts File
 - Append [StevenBlack/hosts](https://github.com/StevenBlack/hosts) into `hosts`; this step can also be done in Little Snitch.
```zsh
curl https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | sudo tee -a /etc/hosts
```

### B) DNSCrypt
> Some VPN applications override DNS settings on connect; may need to reconfigure VPN after setting up a local DNS server (change DNS to 127.0.0.1).
> No need to configure DNSSEC in this step; it will be handled with Dnsmasq.

 1. Install DNSCrypt with `sudo port install dnscrypt-proxy` and load it on startup with `sudo port load dnscrypt-proxy`. Update DNS server settings to point to 127.0.0.1 (Settings > "Network" > Wi-Fi or Eth > Current network "Details" > DNS tab).
 2. Find DNSCrypt's installation location with `port contents dnscrypt-proxy` to get the configuration path (e.g., `/opt/local/share/dnscrypt-proxy/example.toml`).
 3. Edit the file and change listening ports:
```zsh
sudo vi /opt/local/share/dnscrypt-proxy/dnscrypt-proxy.toml
```
```toml
# /opt/local/share/dnscrypt-proxy/dnscrypt-proxy.toml

listen_addresses = ['127.0.0.1:54', '[::1]:54']

# Auto-select servers based on filters (leave server_names commented)
# server_names = []

ipv4_servers = true
ipv6_servers = false
dnscrypt_servers = true
doh_servers = false
odoh_servers = false

require_dnssec = true
require_nolog = true
require_nofilter = true

# Disable resolvers whose operators run our relays
disabled_server_names = [
    'cs-de', 'cs-nl', 'cs-fr', 'cs-austria', 'cs-barcelona',
    'scaleway-fr', 'scaleway-ams',
    'dnscrypt.uk-ipv4', 'dnscrypt.uk-ipv6', 'v.dnscrypt.uk-ipv4', 'v.dnscrypt.uk-ipv6'
]

force_tcp = false
timeout = 5000
keepalive = 30

dnscrypt_ephemeral_keys = true
tls_disable_session_tickets = true

bootstrap_resolvers = ['9.9.9.9:53', '1.1.1.1:53']
ignore_system_dns = true
netprobe_timeout = 60
netprobe_address = '9.9.9.9:53'

block_ipv6 = false
block_unqualified = true
block_undelegated = true
reject_ttl = 10

cache = true
cache_size = 4096
cache_min_ttl = 2400
cache_max_ttl = 86400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 600

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
```
```zsh
sudo vi /etc/resolv.conf

# Edit
nameserver 127.0.0.1
nameserver ::1
```
```zsh
sudo port unload dnscrypt-proxy
sudo port load dnscrypt-proxy
```
 4. Check if current configuration is valid (will not run otherwise):
```zsh
sudo /opt/local/sbin/dnscrypt-proxy -config /opt/local/share/dnscrypt-proxy/dnscrypt-proxy.toml -check

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
 6. Since this guide uses port 54, there still will not be Internet connection until after section 4(C)

### C) Dnsmasq
 1. Install Dnsmasq with `sudo port install dnsmasq` and let it run at startup with `sudo port load dnsmasq`.
 2. Confirm that nothing is running on port 53:
```zsh
sudo lsof +c 15 -Pni UDP:53
```
 3. Again, find the configuration file with `port contents dnsmasq`, which usually is in `/opt/local/etc/dnsmasq.conf.example`. Edit the file:
```zsh
sudo vi /opt/local/etc/dnsmasq.conf
```
```conf
# Find the keys' location and add these lines
server=127.0.0.1#54
server=::1#54
listen-address=::1,127.0.0.1
cache-size=10000
neg-ttl=300

proxy-dnssec
bind-interfaces
bogus-priv
domain-needed
stop-dns-rebind
rebind-localhost-ok
no-resolv
no-poll
min-port=1024
strip-mac
strip-subnet

local=/local/
local=/localhost/
local=/home/
```
 4. Reload Dnsmasq
```zsh
sudo port unload dnsmasq
sudo port load dnsmasq

sudo lsof +c 15 -Pni UDP:53
# dnsmasq 76961 nobody    4u  IPv4 0x60d95e4a7e822dff      0t0  UDP 127.0.0.1:53
# dnsmasq 76961 nobody    6u  IPv6 0xaff5c953c5375455      0t0  UDP [::1]:53
```
 5. Flush previously remaining cache and check connection speed.
```zsh
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder

networksetup -getdnsservers "Wi-Fi"
# 127.0.0.1

scutil --dns | head -10
# nameserver[1] : 127.0.0.1

# First query (goes through the chain)
dig @127.0.0.1 archlinux.org

# Second query (should be faster - cached by dnsmasq)
dig @127.0.0.1 archlinux.org
```
 6. Verify DNS configuration.
```zsh
scutil --dns | head -10

resolver #1
  nameserver[0] : 127.0.0.1
  flags    : Request A records, Request AAAA records
  reach    : 0x00030002 (Reachable,Local Address,Directly Reachable Address)
```
 7. Test if DNSSEC is working:
```zsh
# This should resolve (DNSSEC-signed domain)
dig @127.0.0.1 dnssec.works

# This should FAIL (intentionally broken DNSSEC)
dig @127.0.0.1 fail01.dnssec.works
```
 8. Check if anonymous relays are working
```zsh
sudo lsof +c 15 -Pni UDP:54
# dnscrypt-proxy 34325 root    7u  IPv4 0x3465ee788585df1c      0t0  UDP 127.0.0.1:54
# dnscrypt-proxy 34325 root    9u  IPv6 0xd33867f6c28e6072      0t0  UDP [::1]:54

log show --predicate 'process == "dnscrypt-proxy"' --last 5m
# Filtering the log data using "process == "dnscrypt-proxy""

sudo port unload dnscrypt-proxy
sudo /opt/local/sbin/dnscrypt-proxy -config /opt/local/share/dnscrypt-proxy/dnscrypt-proxy.toml
# Anonymized DNS: routing everything via [anon-cs-de anon-cs-nl anon-cs-fr anon-cs-austria anon-cs-barcelona anon-scaleway-ams anon-kama anon-dnscrypt.uk-ipv4 anon-v.dnscrypt.uk-ipv4 anon-ibksturm anon-meganerd anon-inconnu]
# [2026-01-03 21:41:30] [NOTICE] Anonymizing queries for [dnscry.pt-brisbane-ipv4] via [anon-cs-nl]
# [2026-01-03 21:41:30] [NOTICE] Anonymizing queries for [dnscry.pt-luxembourg-ipv4] via [anon-cs-fr]
...
```
### Persisting resolv.conf
> macOS may overwrite `/etc/resolv.conf` on network changes. Lock it with the immutable flag:

```zsh
# Set correct content
sudo tee /etc/resolv.conf << 'EOF'
nameserver 127.0.0.1
nameserver ::1
EOF

# Make immutable
sudo chflags schg /etc/resolv.conf

# Verify
ls -lO /etc/resolv.conf
# should show "schg" flag
```

```zsh
# To edit later
sudo chflags noschg /etc/resolv.conf
...
sudo chflags schg /etc/resolv.conf
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
<sup>https://wiki.archlinux.org/title/Dnsmasq#DNS_addresses_file_and_forwarding</sup></br>
<sup>https://github.com/drduh/macOS-Security-and-Privacy-Guide?tab=readme-ov-file#dnsmasq</sup>
