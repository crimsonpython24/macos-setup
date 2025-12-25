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

Important: NIST Setup does **not** modify any system behavior on its own. It generates a checklist that validates all system settings reflect the selected policy.
 1. (Optional) download the provided YAML config
 2. Generate the configuration file (there should be a `*.mobileconfig` and a `*compliance.sh` file)
```
cd ~/Desktop/macos_security

# Generate consolidated profile, scripts, and profiles
python3 scripts/generate_guidance.py \
  -P \
  -s \
  -p \
  build/baselines/cnssi-1253_high-cust.yaml
```
 3. Run the compliance script
```
sudo zsh build/cnssi-1253_high-cust/cnssi-1253_high-cust_compliance.sh
```
