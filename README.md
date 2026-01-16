# macOS Setup

Total time needed (from empty system): 70-90 mins, depending on Internet connection

## 0. Basics
 - `launchd` should not be modified like `systemctl` as the former is not designed for user tweaks
   - This rule also applies to "UI skins," custom plugins, etc. since they might break with future updates
   - I.e., one should not change any obscure settings (e.g., `defaults write com.apple.something`) unless they know exactly what they are doing
 - Do not use the admin account besides initializing the machine
 - Do not install any apps as Admin unless necessary, as some should run just fine outside the root directory (e.g. `/Users/warren/Applications`)
   - Said apps will prompt for password if they need privilege escalations regardless, and it is up to one to decide whether to escalate its privilege (install in `/Applications`) or find an alternative.
   - Do not move pre-/auto-installed macOS apps around in Finder, because future updates might break those modifications
 - Only make system-wide configurations (e.g., network interface) or run services such as ClamAV and Santa in Admin; for things like gpg keys, set up in individual users
 - Terminal
   - Ensure that [Secure keyboard](https://fig.io/docs/support/secure-keyboard-input) (in Terminal and iTerm) is enabled
   - Use MacPorts [instead of](https://saagarjha.com/blog/2019/04/26/thoughts-on-macos-package-managers/) Brew
   - Implement some more hardware hardening:
```zsh
# Cold boot attacks
sudo pmset -a destroyfvkeyonstandby 1
sudo pmset -a hibernatemode 25
sudo pmset -a standbydelaylow 0
sudo pmset -a standbydelayhigh 0
sudo pmset -a highstandbythreshold 0
sudo pmset -a powernap 0
sudo pmset -a tcpkeepalive 0
sudo pmset -a proximitywake 0

# Reduce unified log retention
sudo log config --mode "level:off" --subsystem com.apple.diagnosticd

# Prevents SUID programs from dumping core
sudo sysctl -w kern.sugid_coredump=0

# Secure virtual memory
sudo defaults write /Library/Preferences/com.apple.virtualMemory UseEncryptedSwap -bool YES
defaults read /Library/Preferences/com.apple.virtualMemory UseEncryptedSwap
# 1
```
 - Extra Memos
   - Do not install [unmaintained](https://the-sequence.com/twitch-privileged-helper) applications
   - Avoid [Parallels VM](https://jhftss.github.io/Parallels-0-day/), [Electron-based](https://redfoxsecurity.medium.com/hacking-electron-apps-security-risks-and-how-to-protect-your-application-9846518aa0c0) applications (see a full list [here](https://www.electronjs.org/apps)), and apps needing [Rosetta](https://cyberinsider.com/apples-rosetta-2-exploited-for-bypassing-macos-security-protections/) translation

**Note** This guide reflects the "secure, not private" concept in that, although these settings make the OS more secure than the shipped or reinstalled version, this does **not** guarantee privacy from first-party or three-letter-agencies surveillance. 

<sup>https://taoofmac.com/space/howto/switch#best-practices</sup><br/>
<sup>https://news.ycombinator.com/item?id=31864974</sup><br/>
<sup>https://github.com/beerisgood/macOS_Hardening?tab=readme-ov-file</sup>

## 1. CLI Tools
 > Until section 7, this tutorial should be done in admin's GUI because Part (4) requires running a privileged script, but admin cannot read/write warren's files if downloaded there. Run `su - warren` if testing path or commands in that user.

 - Install xcode CLI tools/MacPorts in only one account (admin) to prevent duplicate instances and PATH confusion (technically port can only be installed in admin because it needs sudo access, but still).
 - After `xcode-select --install`, install [MacPorts package](https://www.macports.org/install.php).

## 2. DNS Setup
 > For the following sections, all dependencies can be installed via MacPorts. Avoid using third-party pkg/dmg installers to keep dependency tree clean.

 > Remember to create the non-privileged user first to ensure sections 2-4 also apply to it without having to double-check later.

 1. First create the Warren user (hello!). Log in, go through the setup, and make sure the account works.
 2. Add MacPorts to warren's shells:
```zsh
su - warren
echo 'export PATH=/opt/local/bin:/opt/local/sbin:$PATH' >> ~/.zshrc
echo 'export PATH=/opt/local/bin:/opt/local/sbin:$PATH' >> ~/.bash_profile
exit
```

### A) Hosts File
 - Append [StevenBlack/hosts](https://github.com/StevenBlack/hosts) into `hosts`; this step can also be done in Little Snitch.
```zsh
curl https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | sudo tee -a /etc/hosts
```

### B) DNSCrypt
 > Some VPN applications override DNS settings on connect; may need to reconfigure VPN and make it use the local DNS server (change DNS to 127.0.0.1).
 > No need to configure DNSSEC in this step; it will be handled with Unbound.

 1. Install DNSCrypt with `sudo port install dnscrypt-proxy` and load it on startup with `sudo port load dnscrypt-proxy`.
    - Because there will be no Internet connection until the end of this section, also install Unbound with `sudo port install unbound` and let it run at startup with `sudo port load unbound`.
    - Also copy the [DNSCrypt config](https://github.com/crimsonpython24/macos-setup/blob/master/dns/dnscrypt-proxy.toml) and [Unbound config](https://github.com/crimsonpython24/macos-setup/blob/master/dns/unbound.conf) beforehand.
    - Then, update DNS server settings to point to 127.0.0.1 ("Network" > Wi-Fi or Eth > Current network "Details" > DNS tab).
 2. Find DNSCrypt's installation location with `port contents dnscrypt-proxy` to get configuration files' path.
```zsh
/opt/local/share/dnscrypt-proxy/dnscrypt-proxy.toml
# Paste content
```
 3. Edit the property list to give DNSCrypt startup access:
```zsh
sudo vi /opt/local/etc/LaunchDaemons/org.macports.dnscrypt-proxy/org.macports.dnscrypt-proxy.plist
```
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>org.macports.dnscrypt-proxy</string>
    <key>ProgramArguments</key>
    <array>
      <string>/opt/local/bin/daemondo</string>
      <string>--label=dnscrypt-proxy</string>
      <string>--start-cmd</string>
      <string>/opt/local/sbin/dnscrypt-proxy</string>
      <string>-config</string>
      <string>/opt/local/share/dnscrypt-proxy/dnscrypt-proxy.toml</string>
      <string>;</string>
      <string>--restart-netchange</string>
      <string>--pid=exec</string>
    </array>
    <key>Disabled</key>
    <false />
    <key>KeepAlive</key>
    <true />
    <key>RunAtLoad</key>
    <true />
  </dict>
</plist>
```
 4. Load the proxy:
```zsh
sudo launchctl enable system/org.macports.dnscrypt-proxy
sudo port unload dnscrypt-proxy
sudo port load dnscrypt-proxy
```
 5. Check if current configuration is valid (will not run otherwise):
```zsh
sudo /opt/local/sbin/dnscrypt-proxy -config /opt/local/share/dnscrypt-proxy/dnscrypt-proxy.toml -check
# Remember to reload dnscrypt-proxy after toml change

# If debug: run in foreground with verbose logging
sudo /opt/local/sbin/dnscrypt-proxy -config /opt/local/share/dnscrypt-proxy/dnscrypt-proxy.toml -loglevel 0
```
```zsh
sudo lsof +c 15 -Pni UDP:54
# dnscrypt-proxy 57409 root    7u  IPv4 0xf2ce17b711151ccc      0t0  UDP 127.0.0.1:54
# dnscrypt-proxy 57409 root    9u  IPv6 0x8031285518513383      0t0  UDP [::1]:54
```
 6. After changing the network DNS resolver to use local, ensure that Wi-Fi interfaces use `127.0.0.1` instead of `192.168.x.x`:
```zsh
# Sometimes system will not respect GUI settings
sudo networksetup -setdnsservers "Wi-Fi" 127.0.0.1

networksetup -getdnsservers "Wi-Fi"
# 127.0.0.1

scutil --dns | head -10
# nameserver[0] : 127.0.0.1
```
 7. Again, since this guide routes `dnscrypt-proxy` to port 54, there will not be Internet connection until after section 2(C)

**Note** `dnscrypt-proxy` will take ~15 seconds to load on startup, so there might not be connection immediately after session login.

### C) Unbound
 > The original guide uses `dnsmasq`; however, Dnsmasq will not load `ad` (authenticated data) flag in DNS queries if an entry is cached. Hence this section is replaced with unbound to achieve both caching and auth.

 1. Unbound should already be installed in 2(B). If not, set DNS back to 192.168.0.1, install Unbound, and then change back to 127.0.0.1.
 2. Copy the configurations stored from 2(B) ([here](https://github.com/crimsonpython24/macos-setup/blob/master/dns/unbound.conf) once again)into Unbound:
```zsh
sudo vi /opt/local/etc/unbound/unbound.conf
# Paste content
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
# ;; Got answer:
# ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 38272
# ;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1
# 
# ;; QUESTION SECTION:
# ;archlinux.org.			IN	DNSKEY
# 
# No answer section!
# 
# ;; AUTHORITY SECTION:
# archlinux.org.		3600	IN	SOA	hydrogen.ns.hetzner.com. dns.hetzner.com. 2026010201 86400 10800 3600000 3600
```
```zsh
dig DNSKEY dnssec.works
# ;; Got answer:
# ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 65193
# ;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1
# 
# ;; QUESTION SECTION:
# ;dnssec.works.			IN	DNSKEY
# 
# ;; ANSWER SECTION:
# dnssec.works.		4965	IN	DNSKEY	257 3 8 AwEAAa+YwrBlCwfJzwmsSK87hKFAm+yz0...
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

## 3. Santa Setup
 1. Install the updated release from Northpole on [GitHub](https://github.com/northpolesec/santa/releases).
 2. Grant permissions:
    - "Login Items & Extensions" > "App Background Activity" add Santa.app
    - "Login Items & Extensions" > "Extensions" > "By App" > toggle "Santa"
    - "Login Items & Extensions" > "Extensions" > "By Category" > "Endpoint Security Extensions" toggle Santa daemon
    - "Privacy" > "Full Disk Access" enable Santa Endpoint Security Extension (close and re-open Settings app after Santa install)
 3. Quit and re-open the terminal to check if Santa is running:
```zsh
sudo santactl doctor
```
 4. Add a custom [FAA policy](https://github.com/crimsonpython24/macos-setup/blob/master/policies/faa_policy.plist):
```zsh
sudo mkdir -p /var/db/santa
sudo vi /var/db/santa/faa_policy.plist
# Paste content

sudo chmod 644 /var/db/santa/faa_policy.plist
sudo chown root:wheel /var/db/santa/faa_policy.plist
```
 5. Download the [Configuration Profile](https://github.com/crimsonpython24/macos-setup/blob/master/policies/santa.mobileconfig). Install this profile first before the mSCP config (section 4) because NIST configurations block adding new profiles.
```zsh
cd ~/Desktop && mkdir Profiles && cd Profiles
vi santa.mobileconfig
# Paste content

sudo open santa.mobileconfig
```
 6. Blocking application example (a selected list of banned apps are [in the repo](https://github.com/crimsonpython24/macos-setup/blob/master/policies/prefs/santa_base.json)):
```zsh
santactl fileinfo /System/Applications/Dictionary.app 
# Path                   : /System/Applications/Dictionary.app/Contents/MacOS/Dictionary
# SHA-256                : 85f755c92afe93a52034d498912be0ab475020d615bcbe2ac024babbeed4439f
# SHA-1                  : 0cb8cb1f8d31650f4d770d633aacce9b2fcc5901
# Bundle Name            : Dictionary
# Bundle Version         : 294
# Bundle Version Str     : 2.3.0
# Signing ID             : platform:com.apple.Dictionary

# Use signing ID (will not change even with app update)
sudo santactl rule \
  --block \
  --signingid \
  --identifier platform:com.apple.Dictionary

santactl fileinfo /System/Applications/Dictionary.app 
# Rule                   : Blocked (SigningID)
```
```zsh
# Deprecated appproach: sha-256
sudo santactl rule --block/--remove --sha256 85f755c92afe93a52034d498912be0ab475020d615bcbe2ac024babbeed4439f 
# Added/Removed rule for SHA-256: 85f755c92afe93a52034d498912be0ab475020d615bcbe2ac024babbeed4439f
```
 7. Certain files should be blocked by the FAA policy (because they should be immutable after initialization), e.g.,
```zsh
# Will be created in section 7
cat ~/.ssh/github_ed25519
```
 8. When importing/exporting rules, use:
```zsh
sudo santactl rule --export santa1.json
```

## 4. mSCP Setup
 > [!IMPORTANT]
 > The NIST security compliance project does **not** modify any system behavior on its own. It generates a script that validates if the system reflects the selected policy, and creates a configuration profile that implements some changes.

 > Unless otherwise specified, all commands here should be ran at the project base (`macos_security-*/`).

 1. Download the [repository](https://github.com/usnistgov/macos_security) and the [provided YAML config](https://github.com/crimsonpython24/macos-setup/blob/master/policies/cnssi-1253_cust.yaml) in this repo, or a config from [NIST baselines](https://github.com/usnistgov/macos_security/tree/main/baselines).
```zsh
cd build
mkdir baselines && cd baselines
vi cnssi-1253_cust.yaml
# Paste content
```
 2. Ensure that the `macos_security-*` branch downloaded matches the OS version, e.g., `macos_security-tahoe`.
 3. Install dependencies, recommended within a virtual environment; after this step, warren will also gain paths to python3.14 and its corresponding pip.
```zsh
sudo port install python314
sudo port select --set python python314
sudo port select --set python3 python314
# For admin's shell
echo 'export PATH=/opt/local/bin:/opt/local/sbin:$PATH' >> ~/.zshrc
echo 'export PATH=/opt/local/bin:/opt/local/sbin:$PATH' >> ~/.bash_profile
source ~/.zshrc
source ~/.bash_profile

python --version
# Python 3.14.2
python3 --version
# Python 3.14.2

sudo port install py314-pip 
sudo port select --set pip pip314
sudo port select --set pip3 pip314
rehash (zsh) / hash -r (bash)
pip --version
# pip 25.3
pip3 --version
# pip 25.3
```
```zsh
cd ~/Desktop/Profiles/macos_security-tahoe
python3 -m venv venv
source venv/bin/activate
python3 -m pip install --upgrade pip
pip3 install pyyaml xlwt
```
 4. Small tangent: also check if MacPort libs also work in warren.
```zsh
su - warren
python3 --version
# Python 3.14.2
python --version
# Python 3.14.2
pip3 --version
# pip 25.3 from /opt/local/Library
pip --version
# pip 25.3 from /opt/local/Library
exit
```
 5. Optional: load custom ODVs (organization-defined values)
```zsh
cd ~/Desktop/Profiles/macos_security-tahoe

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
 6. Generate the configuration file (there should be a `*.mobileconfig` and a `*_compliance.sh` file). Note: do not use root for `generate_guidance.py` as it may affect non-root users. The python script will ask for permissions itself (repeat running the script even if it kills itself; it will eventually get all permissions it needs).
```zsh
python3 scripts/generate_guidance.py \
        -P \
        -s \
        -p \
    build/baselines/cnssi-1253_cust.yaml
```
 7. If there is a previous configuration profile installed, remove it in Settings.app first. Run the compliance script.
```zsh
sudo zsh build/cnssi-1253_cust/cnssi-1253_cust_compliance.sh
```
 8. First select option 2 in the script, then option 1 to see the report. Skip option 3 in this step. The compliance percentage should be around 15%.
 9. Install the configuration profile in the Settings app:
```zsh
sudo open build/cnssi-1253_cust/mobileconfigs/unsigned/cnssi-1253_cust.mobileconfig
```
 10. After installing the profile, one way to verify that ODVs are working is to go to "Lock Screen" in Settings and check if "Require password after screen saver begins..." is set to "immediately", as this guide overwrites the default value for that field.
 11. Run the compliance script again (step 7) with options 2, then 1 in that order, i.e., always run a new compliance scan when settings changed. The script should now yield ~80% compliance.
```zsh
sudo zsh build/cnssi-1253_cust/cnssi-1253_cust_compliance.sh
```
 12. Run option 3 and go through all scripts (select `y` for all settings) to apply settings not covered by the configuration profile. There are a handful of them.
 13. Run options 2 and 1 yet again. The compliance percentage should be about 98%. At this point, running option 3 will not do anything, because it does everything it can already, and the script will automatically return to the main menu.
 14. Run option 2, copy the outputs, and find all rules that are still failing. Usually it is these three:
```zsh
os_firewall_default_deny_require
system_settings_filevault_enforce
os_world_writable_library_folder_configure
```
 15. Go inside Settings and manually toggle these two options, the first one as "Block all incoming connections" in "Network" > "Firewall" > "Options", and the second one by enabling "Filevault" under "Privacy and Security" > "Security". Further ensure that `pf` firewall and FileVault are enabled (ALF is enabled by default):
```zsh
ls includes/enablePF-mscp.sh
sudo bash includes/enablePF-mscp.sh

sudo pfctl -a '*' -sr | grep "block drop in all"
# Should output smt like "block drop in all" i.e. default deny all incoming
sudo pfctl -s info
# Should give output

# FileVault
sudo fdesetup status
```
 16. Note from previous step: one might encounter these two warnings.
      - "No ALTQ support in kernel" / "ALTQ related functions disabled": ALTQ is a legacy traffic shaping feature that has been disabled in modern macOS, which does not affect pf firewall at all.
      - "pfctl: DIOCGETRULES: Invalid argument": this occurs when pfctl queries anchors that do not support certain operations, but custom rules in this guide are still loaded (can still see `block drop in all`).
 17. The script should yield 99% compliance by running option 2, then option 1. Run this line:
```zsh
/usr/bin/find /Library -type d -perm -002 ! -perm -1000 ! -xattrname com.apple.rootless 2>/dev/null
# Should only have /Library/AppStore

# Otherwise, run
sudo chmod o-w /Bad/Directory
```
 18. `/Library/AppStore` will fail because that line is SIP-protected, and it is highly discouraged to disable SIP only to modify that one line. Since it is not safe to exclude that directory or modify its permissions, keep the compliance script at 99% is totally fine.

**Note** Restart the device at this point.

**Note** If unwanted banners show up, remove the corresponding files with `sudo rm -rf /Library/Security/PolicyBanner.*`

## 5. AIDE Setup
 1. Install AIDE via MacPorts: `sudo port install aide`; note the post-install message about configuration location: `/opt/local/etc/aide/aide.conf`.
 2. Edit the [configuration file](https://github.com/crimsonpython24/macos-setup/blob/master/policies/aide.conf):
```zsh
sudo vi /opt/local/etc/aide/aide.conf
# Paste content
```
 3. Initialize database:
```zsh
sudo aide --init -L info
#    INFO: read new entries from disk (limit: '(none)', root prefix: '')
#    INFO: write new entries to database: file:/opt/local/var/lib/aide/aide.db.new
#    ...
# AIDE successfully initialized database.
# New AIDE database written to /opt/local/var/lib/aide/aide.db.new
# Number of entries:	~200000
# End timestamp: ... (run time 0m 15-30s)
```
 4. Move database into history directory & verify database:
```zsh
sudo mv /opt/local/var/lib/aide/aide.db.new /opt/local/var/lib/aide/aide.db

ls -lh /opt/local/var/lib/aide/aide.db
# Expected: ~45-50MB
```
 5. Test installation:
```zsh
sudo aide --check
# AIDE found NO differences between database and filesystem. Looks okay!!
# Number of entries:	~200000
...
# End timestamp: ... (run time 1m 0-5s)
```
```zsh
sudo touch /Library/LaunchAgents/com.test.aide.plist

sudo aide --check
# AIDE found differences between database and filesystem!!
# Summary:
#   Total number of entries:	...
#   Added entries:		1
#   Removed entries:		0
#   Changed entries:		1

# ---------------------------------------------------
# Added entries:
# ---------------------------------------------------

# f++++++++++++: /Library/LaunchAgents/com.test.aide.plist
```
```zsh
# Run whenever finished installing legitimate apps/processes
sudo aide --update
sudo mv /opt/local/var/lib/aide/aide.db.new /opt/local/var/lib/aide/aide.db

echo "modified" | sudo tee /Library/LaunchAgents/com.test.aide.plist
sudo aide --check
```
 6. Ensure that database cannot be tampered:
```zsh
ls -la /opt/local/var/lib/aide/aide.db
# -rw------- root admin
```
 7. Cleanup after testing for the next manual/on-demand scan.
```bash
sudo rm /Library/LaunchAgents/com.test.aide.plist
sudo aide --update
sudo mv /opt/local/var/lib/aide/aide.db.new /opt/local/var/lib/aide/aide.db
```

### A) Quick Reference

| Task | Command |
|------|---------|
| Manual check | `sudo aide --check` |
| Update after changes | `sudo aide --update && sudo mv /opt/local/var/lib/aide/aide.db.new /opt/local/var/lib/aide/aide.db` |
| Re-initialize | `sudo aide --init && sudo mv /opt/local/var/lib/aide/aide.db.new /opt/local/var/lib/aide/aide.db` |
| View log | `sudo cat /opt/local/var/log/aide/aide.log` |
| Verbose check | `sudo aide --check -L info` |

### B) Monitored Directories

| Category | Paths | Reason |
|----------|-------|-----|
| LaunchDaemons | `/Library/LaunchDaemons` | Root-level persistence |
| LaunchAgents | `/Library/LaunchAgents`, `~/Library/LaunchAgents` | User-level persistence |
| Applications | `/Applications` | App bundle integrity |
| MacPorts | `/opt/local/bin`, `/opt/local/sbin` | Binary integrity |
| Shell configs | `~/.zshrc`, `~/.bash_profile`, etc. | Backdoor detection |
| SSH | `~/.ssh/config`, `/etc/ssh` | SSH hijacking |
| sudoers | `/etc/sudoers`, `/etc/sudoers.d` | Privilege escalation |
| PAM | `/etc/pam.d` | Auth bypass |
| Auth plugins | `/Library/Security` | Login interception |
| Scripting | `/Library/ScriptingAdditions` | AppleScript injection |
| Input methods | `/Library/Input Methods` | Keylogging |
| Screen savers | `/Library/Screen Savers` | Code execution |
| Santa config | `/var/db/santa` | Security tool tampering |

## 6. Application Install
 > Even when applications are installed in `~/Applications`, e.g., `/Users/warren/Applications`, they might be able to write to `/Library/`, i.e. the root directory, if permissions are accidentally given.

 > Install BlockBlock, KnockKnock, and Little Snitch in this order. It prevents having to re-filter the binaries or miss the binaries' persistence after they are installed.

 > [!NOTE]
 > Although this section applies to `warren`, it is more convenient to run the script inside `admin` because `warren` is not in the sudoers group (and hence cannot run `sudo` commands), and `admin` cannot read/write warren's files because `admin` is not `root`. This is the same note as in section 1.

 1. Ensure that warren is not an admin (so apps should write to `/Users/warren/Library/`):
```zsh
sudo dseditgroup -o edit -d warren -t user admin
```
 2. Force certain `/Library` folders to be inaccessible to apps in `~/Library`.
```zsh
vi ~/Desktop/Profiles/directory_lock.sh
```
```zsh
CRITICAL_DIRS=(
    "/Library/LaunchAgents"
    "/Library/LaunchDaemons"
    "/Library/StartupItems"
    "/Library/PrivilegedHelperTools" 
    "/Library/Security/SecurityAgentPlugins"
    "/Library/DirectoryServices/PlugIns"
    "/System/Library/LaunchAgents"
    "/System/Library/LaunchDaemons"
)

for dir in "${CRITICAL_DIRS[@]}"; do
    sudo chmod +a "user:warren deny add_subdirectory,add_file,writeattr,writeextattr,delete,delete_child" "$dir"
done
```
```zsh
sudo chmod +x ~/Desktop/Profiles/directory_lock.sh
./directory_lock.sh
```
 3. Note for step 2: one can add `/Library/PrivilegedHelperTools` into the directory list, but this will not be created until an application writes to that directory. I.e., this directory will be empty if one runs this script in a fresh system. Also test step 2:
```zsh
ls -led /Library/LaunchAgents
ls -led /Library/LaunchDaemons
ls -led /Library/StartupItems

# drwxr-xr-x+ 3 root  wheel  96 Jan 11 14:30 /Library/LaunchAgents
#  0: user:warren deny add_file,delete,add_subdirectory,delete_child,writeattr,writeextattr
```
 4. Rollback command:
```zsh
sudo chmod -a "user:warren deny add_subdirectory,add_file,writeattr,writeextattr,delete,delete_child" /Library/LaunchAgents
```
 5. When installing application for warren, make sure to create the directory `/Users/warren/Applications` (i.e., `~/Applications`) and drag-and-drop apps there. The "Applications" folder on Finder's sidebar points to `/Applications` (i.e., root). As such, user apps will store files to `~/Library`.

### GnuPG
If any applications are curl'd through Git, use GnuPG instead of gpg:
```zsh
sudo port install gnupg2
sudo port load openldap
which gpg
# /opt/local/bin/gpg
```
And make sure to configure it as in [section 7(B)](https://github.com/crimsonpython24/macos-setup?tab=readme-ov-file#b-gpg-configuration).

### Firefox
 - When using Firefox, use the uploaded [user-overrides.js](https://github.com/crimsonpython24/macos-setup/blob/master/browser/user-overrides.js) in this repo.
 - If macOS does not allow opening the LibreWolf browser, fix the error notification with `xattr -d com.apple.quarantine /Applications/LibreWolf.app`

## 7. Fish Shell
 > For this section, running in warren's GUI is easier (keep zsh as default for admin since that account should not be used besides global settings). Obviously `su - admin` when escalation is needed.

 1. First change the hostname:
```zsh
sudo scutil --set ComputerName "device"
sudo scutil --set LocalHostName "device"
sudo scutil --set HostName "device"
hostname # device
```
 2. Install fish through the admin account:
```zsh
sudo port install fish
```
 3. Switch shells for warren only:
```zsh
sudo sh -c 'echo /opt/local/bin/fish >> /etc/shells'
sudo chpass -s /opt/local/bin/fish warren
```
 4. Add paths to fish:
```fish
# su - warren
fish_add_path /opt/local/bin
fish_add_path /opt/local/sbin
```
 4. Download [Source Code Pro Nerd Font](https://www.nerdfonts.com/font-downloads) and macOS terminal config [in this repo](https://github.com/crimsonpython24/macos-setup/blob/master/shell/fish/default.terminal) (there is nothing special about this terminal config, they are simply personal prefs).
 5. Install [Fisher](https://github.com/jorgebucaran/fisher) with the following extensions:
    - [jethrokuan/z](https://github.com/jethrokuan/z)
    - [PatrickF1/fzf.fish](https://github.com/PatrickF1/fzf.fish) -- depends on `sudo port install fzf fd bat`
    - [jorgebucaran/nvm.fish](https://github.com/jorgebucaran/nvm.fish)
    - [jorgebucaran/autopair.fish](https://github.com/jorgebucaran/autopair.fish)
    - [nickeb96/puffer-fish](https://github.com/nickeb96/puffer-fish)
 6. Configure `fzf` key bindings (note: this step will throw an error if `fzf.fish` is not installed, which one can directly skip):
```fish
echo "fzf_configure_bindings --directory=\cf --git_log=\cl --git_status=\cs --history=\cr --processes=\cp --variables=\cv" >> ~/.config/fish/config.fish
```
 7. Download Node: `nvm install lts`.
 8. Add custom functions:
```fish
~/.config/fish/functions/mkcd.fish

function mkcd
    mkdir -p $argv[1] && cd $argv[1]
end
```
```fish
vi ~/.config/fish/functions/up.fish

function up
  if test -z $argv[1]
    set n 1
  else
    set n $argv[1]
  end
  for i in (seq $n)
    cd ..
  end
end
```
```fish
vi ~/.config/fish/functions/uext.fish

function uext
    find . -type f | perl -ne 'print $1 if m/\.([^.\/]+)$/' | sort -u
end
```
 9. Install tide with `fisher install IlanCosman/tide@v6` and add in [custom configurations](https://github.com/crimsonpython24/macos-setup/blob/master/shell/config.fish).
     - In the initial config, select "Classic" (step 1), "Dark" (step 3), and "24-hour format" (step 4). All other options can go with default.
     - Also edit [custom item context](https://github.com/crimsonpython24/macos-setup/blob/master/shell/_tide_item_context.fish).
```fish
vi ~/.config/fish/config.fish
vi ~/.config/fish/functions/_tide_item_context.fish
```

### A) SSH Configuration
 1. Install new configuration from [ssh-config](https://github.com/crimsonpython24/macos-setup/blob/master/shell/ssh_config):
```fish
mkdir ~/.ssh
vi ~/.ssh/config
chmod 600 ~/.ssh/config
```
 2. Create the sockets directory for multiplexing:
```fish
mkdir -p ~/.ssh/sockets
chmod 700 ~/.ssh/sockets
```
 3. Generate ED25519 key for GitHub:
```fish
ssh-keygen -t ed25519 -a 100 -f ~/.ssh/github_ed25519 -C "github-$(hostname)-$(date +%Y)"
```
 4. Set permissions:
```fish
chmod 700 ~/.ssh
chmod 600 ~/.ssh/config
chmod 600 ~/.ssh/*_ed25519
chmod 644 ~/.ssh/*_ed25519.pub
chmod 600 ~/.ssh/known_hosts
```
 5. Add keys to macOS keychain:
```fish
ssh-add --apple-use-keychain ~/.ssh/github_ed25519
ssh-add -l
```
 6. Add SSH key to GitHub:
```fish
cat ~/.ssh/github_ed25519.pub | pbcopy
# Add to https://github.com/settings/keys as an authentication key, remove trailing new line
```
 7. Test SSH connection:
```fish
ssh -T git@github.com
cat ~/.ssh/known_hosts
# |1|qN7XE853AcGGBmJDT/APv+AiZGU=|qq21+AC5OMD...
```
 8. Run the [test script](https://github.com/crimsonpython24/macos-setup/blob/master/shell/ssh_test.sh) to verify that SSH settings are applied.
```fish
vi ssh_test.sh
# Paste content

chmod +x ssh_test.sh 
./ssh_test.sh
```

**Note** If legacy SSH servers are not working, use the following configuration:
```fish
Host legacy-server
  HostName old.server.com
  # Allow older key exchange for this specific server
  KexAlgorithms +diffie-hellman-group14-sha256,diffie-hellman-group14-sha1
  # Allow older ciphers
  Ciphers +aes128-cbc,aes256-cbc
  # Allow older MACs
  MACs +hmac-sha2-256,hmac-sha1
  # Allow older host key types
  HostKeyAlgorithms +ssh-rsa
  PubkeyAcceptedAlgorithms +ssh-rsa
```

### B) GPG Configuration
 1. Make sure GnuPG is installed: `sudo port install gnupg2`.
 2. Create configuration directory and edit [GPG configuration](https://github.com/crimsonpython24/macos-setup/blob/master/shell/gpg.conf).
```fish
mkdir -p ~/.gnupg
chmod 700 ~/.gnupg
vi ~/.gnupg/gpg.conf
# Edit file
```
 3. Give permissions and check for syntax errors:
```fish
chmod 600 ~/.gnupg/gpg.conf
gpg2 --gpgconf-test
# Should be empty
```
 4. Generate key (RSA and RSA):
```fish
gpg2 --full-generate-key
```
 5. List keys.
```fish
gpg2 --list-secret-keys --keyid-format=long
# sec   rsa4096/ABC123DEF456 2026-01-11 [SC]
gpg2 --armor --export ABC123DEF456
```
 6. Add the key to [GitHub](https://github.com/settings/keys).
 7. Configure Git to use the signing key:
```fish
git config --global user.signingkey ABC123DEF456
git config --global commit.gpgsign true
git config --global gpg.program gpg2
```
 8. Add TTY to fish:
```fish
echo "set -gx GPG_TTY (tty)" >> ~/.config/fish/config.fish
```

### C) Blocking Metadata Creation
 1. Remove sensitive information even when user dictionary/suggestions are off and prevent them from being re-created:
```fish
rm -rfv "~/Library/LanguageModeling/*" "~/Library/Spelling/*" "~/Library/Suggestions/*"
chmod -R 000 ~/Library/LanguageModeling ~/Library/Spelling ~/Library/Suggestions
chflags -R uchg ~/Library/LanguageModeling ~/Library/Spelling ~/Library/Suggestions
```
 2. Clear and lock QuickLook application support metadata:
```fish
rm -rfv "~/Library/Application Support/Quick Look/*"
chmod -R 000 "~/Library/Application Support/Quick Look"
chflags -R uchg "~/Library/Application Support/Quick Look"
```
 3. Clear and lock document revision metadata:
```fish
sudo rm -rfv /.DocumentRevisions-V100/*
sudo chmod -R 000 /.DocumentRevisions-V100
sudo chflags -R uchg /.DocumentRevisions-V100
```
 4. Clear and lock saved application state:
```fish
rm -rfv ~/Library/Saved\ Application\ State/*
rm -rfv ~/Library/Containers/<APPNAME>/Data/Library/Saved\ Application\ State
chmod -R 000 ~/Library/Saved\ Application\ State/
chmod -R 000 ~/Library/Containers/<APPNAME>/Data/Library/Saved\ Application\ State
chflags -R uchg ~/Library/Saved\ Application\ State/
chflags -R uchg ~/Library/Containers/<APPNAME>/Data/Library/Saved\ Application\ State
```
 5. Clear and lock autosave metadata:
```fish
rm -rfv "~/Library/Containers/<APP>/Data/Library/Autosave Information"
rm -rfv "~/Library/Autosave Information"
chmod -R 000 "~/Library/Containers/<APP>/Data/Library/Autosave Information"
chmod -R 000 "~/Library/Autosave Information"
chflags -R uchg "~/Library/Containers/<APP>/Data/Library/Autosave Information"
chflags -R uchg "~/Library/Autosave Information"
```
 6. Clear and lock Siri analytics database:
```fish
rm -rfv ~/Library/Assistant/SiriAnalytics.db
chmod -R 000 ~/Library/Assistant/SiriAnalytics.db
chflags -R uchg ~/Library/Assistant/SiriAnalytics.db
```
 7. After logging into App Store to download Mac apps, clear iCloud user info:
```fish
defaults delete ~/Library/Preferences/com.apple.iTunes.plist StoreUserInfo
defaults delete ~/Library/Preferences/com.apple.iTunes.plist WirelessBuddyID
```

<sup>https://github.com/drduh/macOS-Security-and-Privacy-Guide/tree/master?tab=readme-ov-file#metadata-and-artifacts</sup><br/>

## Footnotes

Reboot and everything should work, even by directly logging into `warren` and not `admin`.
