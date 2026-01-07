# MacOS Setup (WIP)

## 0. Basics
### Administrative Account ("Admin")
#### Principles
 - `launchd` should not be modified like `systemctl` as the former is not designed for user tweaks
   - This rule also applies to "UI skins," custom plugins, etc. since they might break with future updates
   - I.e., one should not change any obscure settings (e.g., `defaults write com.apple.something`) unless they know exactly what they are doing

#### App Installation Guidelines
 - Do not use the admin account besides initializing the machine
 - Do not install any apps as Admin unless necessary, as some should run just fine outside the root directory (i.e. `/Applications`)
   - Said apps will prompt for password if they need privilege escalations regardless
   - Do not move pre-/auto-installed MacOS apps around in Finder, because future updates might break those modifications
 - Only make system-wide configurations (e.g., network interface) or run services such as ClamAV and Santa in Admin
 
### Extra Checklist
 - Terminal
   - Ensure that [Secure keyboard](https://fig.io/docs/support/secure-keyboard-input) (in Terminal and iTerm) is enabled
   - Use MacPorts [instead of](https://saagarjha.com/blog/2019/04/26/thoughts-on-macos-package-managers/) Brew
   - [Prevent](https://github.com/sunknudsen/guides/tree/main/archive/how-to-protect-mac-computers-from-cold-boot-attacks) cold-boot attacks
 - Extra Memos
   - Do not install [unmaintained](https://the-sequence.com/twitch-privileged-helper) applications
   - Avoid [Parallels VM](https://jhftss.github.io/Parallels-0-day/), [Electron-based](https://redfoxsecurity.medium.com/hacking-electron-apps-security-risks-and-how-to-protect-your-application-9846518aa0c0) applications (see a full list [here](https://www.electronjs.org/apps)), and apps needing [Rosetta](https://cyberinsider.com/apples-rosetta-2-exploited-for-bypassing-macos-security-protections/) translation

### Note
This guide reflects the "secure, not private" concept in that, although these settings make the OS more secure than the shipped or reinstalled version, this does **not** guarantee privacy from first-party surveillance. 

<sup>https://taoofmac.com/space/howto/switch#best-practices</sup><br/>
<sup>https://news.ycombinator.com/item?id=31864974</sup><br/>
<sup>https://github.com/beerisgood/macOS_Hardening?tab=readme-ov-file</sup>

## 1. DNS Setup
 > For the following sections, all dependencies (Git, Python3...) can be installed via MacPorts. Install XCode/MacPorts in admin and not in Warren to prevent duplicate instances. Avoid using packages to keep dependency tree clean.

### A) Hosts File
 - Append [StevenBlack/hosts](https://github.com/StevenBlack/hosts) into `hosts`; this step can also be done in Little Snitch.
```zsh
curl https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | sudo tee -a /etc/hosts
```

### B) DNSCrypt
> Some VPN applications override DNS settings on connect; may need to reconfigure VPN after setting up a local DNS server (change DNS to 127.0.0.1).
> No need to configure DNSSEC in this step; it will be handled with Unbound.

 1. Install xcode command-line tools and MacPorts in the admin user.
 2. Install DNSCrypt with `sudo port install dnscrypt-proxy` and load it on startup with `sudo port load dnscrypt-proxy`.
    - Update DNS server settings to point to 127.0.0.1 (Settings > "Network" > Wi-Fi or Eth > Current network "Details" > DNS tab).
    - Because there will be no Internet connection until the end of this section, also install Unbound with `sudo port install unbound` and let it run at startup with `sudo port load unbound`.
 3. Find DNSCrypt's installation location with `port contents dnscrypt-proxy` to get the configuration path.
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
 5. Edit the property list to give DNSCrypt startup access:
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
 6. Load the proxy:
```zsh
sudo launchctl enable system/org.macports.dnscrypt-proxy
sudo port unload dnscrypt-proxy
sudo port load dnscrypt-proxy
```
 7. Check if current configuration is valid (will not run otherwise):
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
 7. After changing the network DNS resolver to use local, ensure that Wi-Fi interfaces use `127.0.0.1` instead of `192.168.x.x`:
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
 8. Again, since this guide routes `dnscrypt-proxy` to port 54, there will not be Internet connection until after section 1(C)

**Note** dnscrypt-proxy will take a few seconds to load on startup, so there might not be connection immediately after session login.

### C) Unbound
> The original guide uses `dnsmasq`; however, Dnsmasq will not load `ad` (authenticated data) flag in DNS queries if an entry is cached. Hence this section is replaced with unbound to achieve both caching and auth.

 1. Unbound should already be installed in 1(B). If not, set DNS back to 192.168.0.1, install Unbound, and then change back to 127.0.0.1.
 2. Create directories and configurations.
```zsh
vi /opt/local/etc/unbound/unbound.conf
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

## 2. Santa Setup
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
 4. Download the [Configuration Profile](https://github.com/crimsonpython24/macos-setup/blob/master/santa.mobileconfig). Install this profile first before the mSCP config (section 3) because the NIST configurations block adding new profiles.
```zsh
vi santa.mobileconfig
# Edit file
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

## 3. mSCP Setup
Important: the security compliance project does **not** modify any system behavior on its own. It generates a script that validates if the system reflects the selected policy, and a configuration profile that implements the changes.

 > Unless otherwise specified, all commands here should be ran at the project base (`macos_security-*/`).

 1. Download the [repository](https://github.com/usnistgov/macos_security) and the [provided YAML config](https://github.com/crimsonpython24/macos-setup/blob/master/cnssi-1253_cust.yaml) in this repo, or a config from [NIST baselines](https://github.com/usnistgov/macos_security/tree/main/baselines). Store the YAML file inside `macos_security-main/build/baselines`.
```zsh
cd build
mkdir baselines && cd baselines
sudo vi cnssi-1253_cust.yaml
```
 2. Ensure that the `macos_security-*` branch downloaded matches the OS version, e.g., `macos_security-tahoe`.
 3. Install dependencies, recommended within a virtual environment.
```zsh
sudo port install python314
sudo port select --set python python314
sudo port select --set python3 python314
```
```zsh
cd ~/Desktop/Profiles/macos_security-tahoe
python3 -m venv venv
source venv/bin/activate
python3 -m pip install --upgrade pip
pip3 install pyyaml xlwt
```
 4. Optional: load custom ODVs (organization-defined values)
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
 5. Generate the configuration file (there should be a `*.mobileconfig` and a `*_compliance.sh` file). Note: do not use root for `generate_guidance.py` as it may affect non-root users. The python script will ask for permissions itself (repeat running the script even if it kills itself; it will eventually get all permissions it needs).
```zsh
python3 scripts/generate_guidance.py \
        -P \
        -s \
        -p \
    build/baselines/cnssi-1253_cust.yaml
```
 6. If there is a previous profile installed, remove it in Settings first. Run the compliance script.
```zsh
sudo zsh build/cnssi-1253_cust/cnssi-1253_cust_compliance.sh
```
 7. First select option 2 in the script, then option 1 to see the report. Skip option 3 in this step. The compliance percentage should be around 15%. Exit the tool.
 8. Install the configuration profile (one might have to open the Settings app to install the profile):
```zsh
cd build/cnssi-1253_cust/mobileconfigs/unsigned
sudo open cnssi-1253_cust.mobileconfig
```
 9. After installing the profile, one way to verify that ODVs are working is to go to "Lock Screen" in Settings and check if "Require password after screen saver begins..." is set to "immediately", as this guide overwrites the default value for that field.
 10. Exit (if not already) and run the compliance script again (step 7) with options 2, then 1 in that order. The script should now yield ~80% compliance.
```zsh
sudo zsh build/cnssi-1253_cust/cnssi-1253_cust_compliance.sh
```
 11. Run option 3 and go through all scripts (select `y` for all settings) to apply settings not covered by the configuration profile. There will be a handful of them.
 12. Run options 2 and 1 yet again. The compliance percentage should be about 98%. At this point, running option 3 will not do anything, because it does everything it can already, and the script will automatically return to the main menu.
 13. Run option 2, copy the outputs, and find all rules that are still failing. Usually it is these two:
```zsh
os_firewall_default_deny_require
system_settings_filevault_enforce
```
 14. Go inside Settings and manually toggle these two options, the first one as "Block all incoming connections" in "Network" > "Firewall" > "Options", and the second one by enabling "Filevault" under "Privacy and Security" > "Security". Further ensure that `pf` firewall and FileVault are enabled (ALF is enabled by default):
```zsh
ls includes/enablePF-mscp.sh
sudo bash includes/enablePF-mscp.sh

sudo pfctl -a '*' -sr | grep "block drop in all"
# Should output smt like "block drop in all" i.e. default deny all incoming
sudo pfctl -s info
# Should be running

# FileVault
sudo fdesetup status
```
 15. Note from previous step: one might encounter these two warnings
   - "No ALTQ support in kernel" / "ALTQ related functions disabled": ALTQ is a legacy traffic shaping feature that has been disabled in modern macOS, which does not affect pf firewall at all.
   - "pfctl: DIOCGETRULES: Invalid argument": this occurs when pfctl queries anchors that do not support certain operations, but custom rules in this guide are still loaded (can still see `block drop in all`).
 16. The script should yield 100% compliance by running option 2, then option 1. Restart the device.

**Note** if unwanted banners show up, remove the corresponding files with `sudo rm -rf /Library/Security/PolicyBanner.*`
