## 2. ClamAV Setup (MacPorts)

> **Note on Email Notifications:** The scan scripts include email alerting, but this is **optional**. If email is not configured, the scripts will still work - alerts simply won't be sent. To enable email notifications, complete the "Email Notifications Setup" section later in this guide.

> **Note on User Privileges:** This guide is configured for an unprivileged user `warren`. System daemons run as root for proper access, while user-level agents run as `warren`.

### Part 1: Base ClamAV Installation
 1. This ClamAV port creates all configurations already. Run `su - admin` in Warren to get the privileged shell and access MacPorts.
 2. Install ClamAV from MacPorts: `sudo port install clamav-server`. Do **not** execute `sudo port load clamav-server` because doing so will conflict with this guide's startup scripts. Also do not give `daemondo` full-disk access because it is unnecessary.
 3. Set up ClamAV directories with proper ownership (root-owned for security):
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
 4. Set up Freshclam:
```zsh
sudo vi /opt/local/etc/freshclam.conf
```
```conf
# Comment out:
# Example

# Uncomment
UpdateLogFile /opt/local/var/log/clamav/freshclam.log
NotifyClamd /opt/local/etc/clamd.conf
DatabaseDirectory /opt/local/share/clamav
DatabaseOwner root
```
```zsh
sudo touch /opt/local/var/log/clamav/freshclam.log
sudo chown root:wheel /opt/local/var/log/clamav/freshclam.log
sudo chmod 644 /opt/local/var/log/clamav/freshclam.log
```
 5. Set up Clamd:
```zsh
sudo vi /opt/local/etc/clamd.conf
```
```conf
# Comment out:
# Example

# Uncomment
LocalSocket /opt/local/var/run/clamav/clamd.socket
PidFile /opt/local/var/run/clamav/clamd.pid
Foreground yes
LogFile /opt/local/var/log/clamav/clamd.log
DatabaseDirectory /opt/local/share/clamav
LogVerbose yes
LogRotate yes
LogFileMaxSize 10M

# Add to end (exclusions for performance)
ExcludePath ^/Users/warren/\.git/
ExcludePath ^/Users/warren/node_modules/
ExcludePath ^/Users/warren/Library/Caches/
ExcludePath ^/Users/warren/\.Trash/
ExcludePath ^/Users/warren/Library/Application Support/Knowledge/
ExcludePath ^/Users/warren/Library/Application Support/com\.apple\.TCC/
ExcludePath ^/Users/warren/Library/Application Support/AddressBook/
ExcludePath ^/Users/warren/Library/Application Support/FaceTime/
ExcludePath ^/Users/warren/Library/Application Support/CallHistoryDB/
ExcludePath ^/Users/warren/Library/Autosave Information/
ExcludePath ^/Users/warren/\.viminfo$
ExcludePath ^/Users/warren/\.bnnsir$
ExcludePath ^/Users/warren/Library/Group Containers/
ExcludePath ^/Users/warren/Library/Daemon Containers/
ExcludePath ^/Users/warren/Library/Biome/
ExcludePath ^/private/var/folders/
ExcludePath ^/System/
```
 6. Wrap `clamd` inside an application to give it FDA access (macOS Tahoe 26+):
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

sudo codesign --force --sign - /Applications/ClamAVDaemon.app
```
 7. Wrap `clamdscan` (the client) inside an application to give it FDA access (required for scanning files as unprivileged user):
```zsh
sudo mkdir -p /Applications/ClamdScan.app/Contents/MacOS

sudo tee /Applications/ClamdScan.app/Contents/MacOS/ClamdScan << 'EOF'
#!/bin/bash
exec /opt/local/bin/clamdscan --fdpass "$@"
EOF

sudo chmod +x /Applications/ClamdScan.app/Contents/MacOS/ClamdScan

sudo tee /Applications/ClamdScan.app/Contents/Info.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>ClamdScan</string>
    <key>CFBundleIdentifier</key>
    <string>com.personal.clamdscan</string>
    <key>CFBundleName</key>
    <string>ClamdScan</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
</dict>
</plist>
EOF

sudo codesign --force --sign - /Applications/ClamdScan.app
```
 8. Create `clamd` LaunchDaemon:
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
 9. Wrap `freshclam` inside an application (for consistency, though FDA is not strictly required):
```zsh
sudo mkdir -p /Applications/FreshclamDaemon.app/Contents/MacOS

sudo tee /Applications/FreshclamDaemon.app/Contents/MacOS/FreshclamDaemon << 'EOF'
#!/bin/bash
exec /opt/local/bin/freshclam "$@"
EOF

sudo chmod +x /Applications/FreshclamDaemon.app/Contents/MacOS/FreshclamDaemon

sudo tee /Applications/FreshclamDaemon.app/Contents/Info.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>FreshclamDaemon</string>
    <key>CFBundleIdentifier</key>
    <string>com.personal.freshclam-daemon</string>
    <key>CFBundleName</key>
    <string>FreshclamDaemon</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
</dict>
</plist>
EOF

sudo codesign --force --sign - /Applications/FreshclamDaemon.app
```
 10. Create Freshclam LaunchDaemon (for automatic database updates):
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
        <string>/Applications/FreshclamDaemon.app/Contents/MacOS/FreshclamDaemon</string>
    </array>
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
 11. Add the following apps to FDA (**Settings > Privacy & Security > Full Disk Access**):
   - `/Applications/ClamAVDaemon.app`
   - `/Applications/ClamdScan.app`
   - `/Applications/FreshclamDaemon.app`
 12. Run this sequence to start Clamd fresh and ensure that `freshclam` notifies `clamd` daemon:
```zsh
sudo rm -f /opt/local/var/log/clamav/freshclam.log.lock
sudo rm -f /opt/local/var/run/clamav/freshclam.pid

# This should be empty
lsof | grep freshclam.log

sudo rm /opt/local/var/log/clamav/freshclam.log
sudo touch /opt/local/var/log/clamav/freshclam.log
sudo chown root:wheel /opt/local/var/log/clamav/freshclam.log
sudo chmod 644 /opt/local/var/log/clamav/freshclam.log

sudo launchctl load /Library/LaunchDaemons/com.personal.clamd.plist

# Important: run as sudo
sudo freshclam
# Clamd successfully notified about the update.

sudo launchctl load /Library/LaunchDaemons/com.personal.freshclam.plist
```
 13. **Checkpoint** - Verify base installation:
```zsh
# Check daemons are running, wait for freshclam to finish first
sleep 5
sudo launchctl list | grep com.personal
# 1234	0	com.personal.clamd
# -	0	com.personal.freshclam

# Check socket exists
ls -la /opt/local/var/run/clamav/clamd.socket
# srw-rw-rw-  1 root  wheel  0 Dec 28 17:45 /opt/local/var/run/clamav/clamd.socket
```
```zsh
# Switch back to Warren
su - warren

# Add MacPorts to PATH (one-time setup)
echo 'export PATH="/opt/local/bin:/opt/local/sbin:$PATH"' >> ~/.zshrc
echo 'export PATH="/opt/local/bin:/opt/local/sbin:$PATH"' >> ~/.zprofile
echo 'alias clamdscan="/Applications/ClamdScan.app/Contents/MacOS/ClamdScan"' >> ~/.zshrc
source ~/.zshrc

# Check ClamAV version and database (use wrapped clamdscan)
/Applications/ClamdScan.app/Contents/MacOS/ClamdScan --version
# ClamAV 1.5.1/27863/Sun Dec 28 15:26:03 2025

# Test scan with EICAR (use wrapped clamdscan for FDA access)
cd ~/Downloads
curl -L -o eicar-test.txt https://secure.eicar.org/eicar.com.txt
/Applications/ClamdScan.app/Contents/MacOS/ClamdScan -i eicar-test.txt
# eicar-test.txt: Eicar-Test-Signature FOUND
rm -f eicar-test.txt
```

**Note** EICAR is a dummy file that only contains a signature that should notify an antivirus. It does not contain anything malicious.

**Note** macOS may show background app notifications from "Joshua Root" when ClamAV services run. This is normal - Joshua Root is the MacPorts developer who signs the packages.

### Part 2: Daily Scan Setup

> Run Part 2 commands as admin (`su - admin` if currently in warren).

 1. Create root-owned directories for logs and quarantine:
```zsh
sudo mkdir -p /var/root/clamav-logs
sudo chown root:wheel /var/root/clamav-logs
sudo chmod 700 /var/root/clamav-logs

sudo mkdir -p /var/root/quarantine
sudo chown root:wheel /var/root/quarantine
sudo chmod 700 /var/root/quarantine
```
 2. Wrap `clamscan` inside an application to give it FDA access (required for file scanning):
```zsh
sudo mkdir -p /Applications/ClamScan.app/Contents/MacOS

sudo tee /Applications/ClamScan.app/Contents/MacOS/ClamScan << 'EOF'
#!/bin/bash
exec /opt/local/bin/clamscan "$@"
EOF

sudo chmod +x /Applications/ClamScan.app/Contents/MacOS/ClamScan

sudo tee /Applications/ClamScan.app/Contents/Info.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>ClamScan</string>
    <key>CFBundleIdentifier</key>
    <string>com.personal.clamscan</string>
    <key>CFBundleName</key>
    <string>ClamScan</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
</dict>
</plist>
EOF

sudo codesign --force --sign - /Applications/ClamScan.app
```
 3. Add `/Applications/ClamScan.app` to FDA (**Settings > Privacy & Security > Full Disk Access**).
 4. **Verify** `ClamScan.app` works before proceeding:
```zsh
# Create test file
sudo curl -L -o /Users/warren/Downloads/eicar-test.txt https://secure.eicar.org/eicar.com.txt
sudo chown warren:staff /Users/warren/Downloads/eicar-test.txt

# Verify file content is correct
cat /Users/warren/Downloads/eicar-test.txt
# Should show: X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*

# Test ClamScan.app directly
sudo /Applications/ClamScan.app/Contents/MacOS/ClamScan /Users/warren/Downloads/eicar-test.txt
# Expected: /Users/warren/Downloads/eicar-test.txt: Eicar-Test-Signature FOUND

# If NOT found, ClamScan.app is missing FDA - re-add it and try again
rm -f /Users/warren/Downloads/eicar-test.txt
```
 5. Create the daily scan script (in this [repo](https://github.com/crimsonpython24/macos-setup/blob/master/clamav-scan.sh)):
```zsh
sudo mkdir -p /usr/local/bin 
sudo vi /usr/local/bin/clamav-scan.sh
```
```zsh
sudo chmod +x /usr/local/bin/clamav-scan.sh
```
 6. Create the ClamAVScan.app wrapper that calls the scan script:
```zsh
sudo mkdir -p /Applications/ClamAVScan.app/Contents/MacOS

sudo tee /Applications/ClamAVScan.app/Contents/MacOS/ClamAVScan << 'EOF'
#!/bin/bash
/usr/local/bin/clamav-scan.sh /Users/warren
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

# Code sign the app
sudo codesign --force --sign - /Applications/ClamAVScan.app
```
 7. Create LaunchDaemon for daily scans (runs at 4am as root):
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
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>4</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>/var/root/clamav-logs/clamscan-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/var/root/clamav-logs/clamscan-stderr.log</string>
</dict>
</plist>
```
```zsh
sudo launchctl load /Library/LaunchDaemons/com.personal.clamscan.plist
```
 8. **Checkpoint** - Verify daily scan setup (run as admin):
```zsh
# Re-verify daemons from Part 1
sudo launchctl list | grep com.personal
# 1234	0	com.personal.clamd
# -	0	com.personal.freshclam
# -	0	com.personal.clamscan -- there is no PID because it only runs periodically

# Create test file in warren's Downloads
sudo curl -L -o /Users/warren/Downloads/eicar-daily-test.txt https://secure.eicar.org/eicar.com.txt
sudo chown warren:staff /Users/warren/Downloads/eicar-daily-test.txt

# Test daily scan manually (scans /Users/warren by default)
sudo /usr/local/bin/clamav-scan.sh
# Expected: 
#  - "1 infected file(s) found" message
#  - file moved to /var/root/quarantine/
#  - dialog notification appears
#  - email NOT sent yet (email setup is next)
# Note: Some "errors" are normal (macOS protected files that can't be scanned)

# Check log was created
sudo tail -20 /var/root/clamav-logs/scan-$(date +%F).log
# ----------- SCAN SUMMARY -----------
# Infected files: 1
# ...

# Check quarantine
sudo ls /var/root/quarantine/
# eicar-daily-test.txt

# Clean up quarantine for next tests
sudo rm -rf /var/root/quarantine/*
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
 6. **Checkpoint** - Verify email AND re-verify Parts 1-2:
```zsh
# test email directly
echo "Test email from ClamAV setup" | mail -s "ClamAV Test" yjwarrenwang@gmail.com
sleep 5
mailq
# Mail queue is empty
# check inbox for the test email, might need a minute

# Re-verify all daemons
sudo launchctl list | grep com.personal
# 1234	0	com.personal.clamd
# -	0	com.personal.freshclam
# -	0	com.personal.clamscan

# Full integration test with email
curl -L -o ~/Downloads/eicar-email-test.txt https://secure.eicar.org/eicar.com.txt
sudo /usr/local/bin/clamav-scan.sh /Users/warren/Downloads
# Expected:
#   - scan completes
#   - dialog notification appears
#   - email IS sent this time (check inbox)
#   - log shows "Email sent successfully"

sudo tail -10 /var/root/clamav-logs/scan-$(date +%F).log
# "Email sent successfully" somewhere
sudo rm -rf /var/root/quarantine/*
```

### Part 4: On-Access Scanning
> There is no official on-access scanning on macOS (only Linux via `fanotify`). This uses `fswatch` as a workaround for real-time file monitoring.

 1. Install `fswatch`:
```zsh
sudo port install fswatch
```
 2. Create user-level directories for on-access logs and quarantine:
```zsh
mkdir -p /Users/warren/clamav-logs
mkdir -p /Users/warren/quarantine
```
 3. Create the on-access scan script (also in [this repo](https://github.com/crimsonpython24/macos-setup/blob/master/clamav-onaccess.sh)):
```zsh
sudo vi /usr/local/bin/clamav-onaccess.sh
# ...
```
```zsh
sudo chmod +x /usr/local/bin/clamav-onaccess.sh
```
 4. Create LaunchAgent (runs as user, not system, so do not give sudo):
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
 5. Load the LaunchAgent:
```zsh
launchctl load ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist
```
 6. **Checkpoint** - Full system verification (verifies everything):
```zsh
# Verify all daemons
sudo launchctl list | grep com.personal
# 1234	0	com.personal.clamd
# -	0	com.personal.freshclam
# -	0	com.personal.clamscan

launchctl list | grep clamav-onaccess
# 1825	0	com.personal.clamav-onaccess

ps aux | grep fswatch | grep -v grep
# /opt/local/bin/fswatch -0 -r -l 2...

# Verify clamd socket
ls -la /opt/local/var/run/clamav/clamd.socket
# srw-rw-rw-  1 root  wheel  0 Dec 28 17:45 /opt/local/var/run/clamav/clamd.socket

# Test on-access scanning
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

# Test small file (should not alert, <50B unlikely to be virus)
echo "normal content" > ~/Downloads/clean-test.txt
# Expected in log: "Clean"

# Test clean file (should not alert)
echo "longer content that should be larger than 50 bytes" > ~/Downloads/clean-test2.txt
# Expected in log: "Clean"

# Verify email
mailq
# "Mail queue is empty"

# Check all logs exist
ls -la ~/clamav-logs/
# Expected: onaccess-YYYY-MM-DD.log
sudo ls -la /var/root/clamav-logs/
# Expected: scan-YYYY-MM-DD.log
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

launchctl unload ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist
launchctl load ~/Library/LaunchAgents/com.personal.clamav-onaccess.plist

sudo launchctl start com.personal.clamscan
```

### Ref: Log Locations
```zsh
# Daily scan (root-owned)
sudo cat /var/root/clamav-logs/scan-$(date +%F).log

# On-access (user-owned)
cat ~/clamav-logs/onaccess-$(date +%F).log

# ClamAV daemon (root-owned)
sudo cat /opt/local/var/log/clamav/clamd.log

# Freshclam (root-owned)
sudo cat /opt/local/var/log/clamav/freshclam.log
```

<sup>https://paulrbts.github.io/blog/software/2017/08/18/clamav/</sup><br/>
<sup>https://blog.csdn.net/qq_60735796/article/details/156052196</sup>

