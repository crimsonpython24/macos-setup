# macos-setup

## Basics

1. Start by creating an admin account on a clean system install, not the actual day-to-day user account<sup>[1]</sup>. Create the personal account once the admin account is set up. ClamAV, etc. should run on startup and be accessible on the user account, and said processes are meant *not* to be changed from any non-admin accounts.
2. Install base stuffs
   1. Iterm2/LibreWolf<sup>[2]</sup>
   2. Macports<sup>[3]</sup>
   3. Fish shell through port<sup>[4]</sup>

<sub>
  [1] https://taoofmac.com/space/howto/switch#best-practices<br/>
  [2] LibreWolf has an ARM-based version. The website download link defaults to the x86-64 version. You can use Alacritty, Kitty, or any terminal emulator you prefer.<br/>
  [3] This guide prefers Macports over Homebrew, see https://saagarjha.com/blog/2019/04/26/thoughts-on-macos-package-managers/<br/>
  [4] Installing packages through port allows updates and a better dependency tree (e.g., if one of fish or some port package has an update, either's new dependencies won't break the other's, and this applies to packages beyond fish)
</sub>

## ClamAV 

1. Start by installing the `clamav-server` port (insert post-installation image): https://ports.macports.org/port/clamav-server/
   - Make sure the settings/permissions are properly given (e.g., full-disk access to daemons) + comment out the Example lines
   - Do not install the ClamAV pkg file, which installs to `/usr/local/` (will hence conflict with the `clamav-server` port, which will always install the `clamav` port as a dependency, so you might end up with two different ClamAV instances)
   - ClamAV on Mac alone does **not** provide background utilities (in contrast to something like `clamav-daemon` on Debian), so a wrapper is needed
2. Settings to validate:
   - `DatabaseMirror database.clamav.net` — enabled (freshclam.conf)
   - `LocalSocket /tmp/clamd.socket` - enabled (clamd.conf)
   - *Remark* these should be automatically configured in `clamav-server`, but it doesn't hurt to double-check
3. Create a launchd file for automatic updates (in case the `clamav-server` daemons don't work):
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
       <key>Label</key>
       <string>com.personal.freshclam</string>
       <key>ProgramArguments</key>
   	<array>
   	    <string>/usr/local/bin/freshclam</string>
   		<string>-d</string>
   	</array>
       <key>KeepAlive</key>
       <false/>
       <key>RunAtLoad</key>
       <true/>
       <key>StartInterval</key>
           <integer>43200</integer>
   </dict>
   </plist>
   ```
   Check if this loads:
   ```bash
   ~> sudo launchctl load /Library/LaunchDaemons/com.personal.freshclam.plist
   ~> sudo launchctl list | grep com.personal.freshclam
   ~> ls -l /opt/local/var/log/clamav/freshclam.log
   ```
4. Daily scans script<sup>[1]</sup>:
   ```bash
   ~> vi ~/scripts/ClamAV
   ----
   SCAN_DIR="/Users"
   LOG_FILE="/var/log/clamav/freshclam-user.log"
   echo `date +%F-%H%M` >> $LOG_FILE
   /opt/local/bin/clamscan -i -r --move=/Users/admin/quarantine $SCAN_DIR >> $LOG_FILE
   ```
   Remarks:
     - Validate that the clamscan directory is correct (this may vary based on different installations)
     - Make sure that the "Users/admin/quarantine" directory is already created (the script may not have access to create folders). If not, create one.
     - In this step, use a separate log file (which is ours, and is not clamav's own log) and chown it. Do **not** replace or chown ClamAV's self-created log file, as doing so may create read/write permission problems, given that ClamAV's log files should belong to the _clamav user.
5. Load the scan script from step 4:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   /Users/admin/.viminfo: Access denied
   <?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
   <plist version="1.0">
   <dict>
       <key>Label</key>
       <string>com.personal.clamscan</string>
       <key>Program</key>
       <string>/Users/admin/Scripts/clamscan</string>
       <key>KeepAlive</key>
       <false/>
       <key>RunAtLoad</key>
       <false/>
       <key>StartCalendarInterval</key>
       <dict>
           <key>Hour</key>
           <integer>18</integer>
           <key>Minute</key>
           <integer>28</integer>
       </dict>
       <key>StandardErrorPath</key>
       <string>/var/log/clamscan.stderr</string>
   </dict>
   </plist>
   ```
   - After saving, run the "/Users/admin/Scripts/clamav" script to give it all the permission it needs, such as Photos, Desktops, and Downloads.
   - Once again, `clamd` needs to be separately configured from freshclam to run it at startup/as a service<sup>[2]</sup>
   - There should be no need to touch/chmod 600/chown clamav /var/log/freshclam.log (or rather, /opt/local/var/log/clamav/clamav.log)<sup>Revision needed</sup>

<sub>
  [1] https://paulrbts.github.io/blog/software/2017/08/18/clamav/<br/>
  [2] https://docs.clamav.net/manual/Installing/Packages.html#macports
</sub>
