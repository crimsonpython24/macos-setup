# MacOS Setup (WIP, might contain incorrect information)

## 0. Basics
### Administrative Account
#### Principles
 - Do not change `launchd` like one would to `systemctl` because they are not designed for user tweaks
   - This rule also applies to "UI skins", "custom plugins", etc. since they will break sooner or later
   - Unless they know what they are doing or is strictly necessary, one should not change any obscure setting (e.g., `defaults write com.apple.something`)

#### Applications
 - Do not use the admin account besides initializing the machine
 - Do not install any application as Admin, as apps should run just fine without being installed from the root directory (`/Applications`)
   - Said apps will prompt for a password if they need escalation regardless
   - Do not move pre-/auto-installed MacOS apps in Finder, because doing so might break those apps in future updates
 - Only make system-wide configurations (e.g., network interfaces) or run services such as ClamAV and Santa in Admin
   - If the administrative binaries configured in this guide do not affect the unprivileged user, double-check config files because they should
   - Also install security apps (e.g., Murus, pf configurators) in Admin account, because they work better with full-system access

### General Changes
 - Load NIST's MacOS Security configuration with [CNSSI-1253_high](https://github.com/usnistgov/macos_security/blob/2ac6b9078edf2cc521ca90450111e32de164916a/baselines/cnssi-1253_high.yaml)
   - CNSSI-1253 is the selected baseline in this example as it covers most settings without requiring an antivirus
   - Run the configurator to alter some rules, e.g., disable smart card for those who do not have one
 - Disable auto-opening files and Top Sites (I hate it) after downloading in Safari
 - Turn on Lockdown Mode because why not (considerable since yours truly is quite solitary and is unbothered by its effects)
 - If one does not want to load the NIST configuration, they can choose the follows instead:
   - Enable FileVault, Firewall, and [GateKeeper](https://dev.to/reybis/enable-gatekeeper-macos-1klh), and disable AirDrop, [Remote Login](https://support.apple.com/en-gb/guide/mac-help/mchlp1066/mac), and [Remote Desktop](https://support.apple.com/en-za/guide/mac-help/mh11851/mac)
   - Disable [Bonjour](https://www.tenable.com/audits/items/CIS_Apple_macOS_10.13_v1.1.0_Level_2.audit:d9dcee7e4d2b8d2ee54f437158992d88) and [Guest User](https://discussions.apple.com/thread/253375291?sortBy=rank) if possible, _although_ these two are included in CIS Level 2 if one enforces those policies
   - Disable all [remote access](https://support.apple.com/guide/remote-desktop/enable-remote-management-apd8b1c65bd/mac) sharing settings
   - Even if NIST configurations are active, it does not hurt to go into the System Preferences app and check the corresponding settings
 - Disable location at all times (personal preference; can be adjusted)
 - Use MacPorts [instead of](https://saagarjha.com/blog/2019/04/26/thoughts-on-macos-package-managers/) Brew

### Extra Checklist
 - Ensure that [Full Security](https://support.apple.com/en-za/guide/mac-help/mchl768f7291/mac), [SIP](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html), and [accessory access](https://support.apple.com/en-za/guide/deployment/depf8a4cb051/web) are managed
 - Do not keep [unmaintained](https://the-sequence.com/twitch-privileged-helper) applications
 - Avoid [Parallels VM](https://jhftss.github.io/Parallels-0-day/), [Electron-based](https://redfoxsecurity.medium.com/hacking-electron-apps-security-risks-and-how-to-protect-your-application-9846518aa0c0) applications (see a full list [here](https://www.electronjs.org/apps)), and [Rosetta](https://cyberinsider.com/apples-rosetta-2-exploited-for-bypassing-macos-security-protections/) translation
 - Enable [secure keyboard](https://fig.io/docs/support/secure-keyboard-input) in Terminal and iTerm
  
### Very First CLI Setting
 - [Disable](https://github.com/sunknudsen/guides/tree/main/archive/how-to-protect-mac-computers-from-cold-boot-attacks) cold-boot attacks
```
sudo pmset -a destroyfvkeyonstandby 1 hibernatemode 25 standbydelaylow 0 standbydelayhigh 0
```

### Note
This section reflects the "secure, not private" concept in that, although these settings make the OS more secure than the shipped or reinstalled version, this does **not** guarantee privacy from first-party surveillance. 

<sup>https://taoofmac.com/space/howto/switch#best-practices</sup><br/>
<sup>https://support.addigy.com/hc/en-us/articles/4403726652435-Recommended-macOS-Security-Configurations</sup><br/>
<sup>https://news.ycombinator.com/item?id=31864974</sup><br/>
<sup>https://github.com/beerisgood/macOS_Hardening?tab=readme-ov-file</sup>
