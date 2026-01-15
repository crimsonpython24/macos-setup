#!/usr/bin/env fish

set -l RED '\033[0;31m'
set -l GREEN '\033[0;32m'
set -l YELLOW '\033[1;33m'
set -l NC '\033[0m' # No Color

function print_header
    echo ""
    echo "========================================="
    echo $argv[1]
    echo "========================================="
end

function check_pass
    echo -e "$GREEN✓ PASS:$NC $argv[1]"
end

function check_fail
    echo -e "$RED✗ FAIL:$NC $argv[1]"
end

function check_warn
    echo -e "$YELLOW⚠ WARN:$NC $argv[1]"
end

# Start verification
print_header "SSH Configuration Verification"

# Check 1: SSH directory exists
print_header "1. Directory Structure"
if test -d ~/.ssh
    check_pass "~/.ssh directory exists"
    set perms (stat -f "%Lp" ~/.ssh)
    if test $perms = "700"
        check_pass "~/.ssh has correct permissions (700)"
    else
        check_fail "~/.ssh has incorrect permissions ($perms). Should be 700"
    end
else
    check_fail "~/.ssh directory does not exist"
    exit 1
end

# Check 2: Sockets directory
if test -d ~/.ssh/sockets
    check_pass "~/.ssh/sockets directory exists"
    set perms (stat -f "%Lp" ~/.ssh/sockets)
    if test $perms = "700"
        check_pass "~/.ssh/sockets has correct permissions (700)"
    else
        check_fail "~/.ssh/sockets has incorrect permissions ($perms). Should be 700"
    end
else
    check_fail "~/.ssh/sockets directory does not exist"
end

# Check 3: Config file exists and has correct permissions
print_header "2. Configuration File"
if test -f ~/.ssh/config
    check_pass "~/.ssh/config exists"
    set perms (stat -f "%Lp" ~/.ssh/config)
    if test $perms = "600"
        check_pass "~/.ssh/config has correct permissions (600)"
    else
        check_fail "~/.ssh/config has incorrect permissions ($perms). Should be 600"
    end
else
    check_fail "~/.ssh/config does not exist"
    exit 1
end

# Check 4: Config syntax validation
print_header "3. Configuration Syntax"
if ssh -G github.com >/dev/null 2>&1
    check_pass "SSH config syntax is valid"
else
    check_fail "SSH config has syntax errors"
    ssh -G github.com
end

# Check 5: Key files
print_header "4. SSH Keys"
set -l found_keys 0
for key in ~/.ssh/*_ed25519
    if test -f $key
        set found_keys (math $found_keys + 1)
        set key_name (basename $key)
        check_pass "Found key: $key_name"
        
        # Check private key permissions
        set perms (stat -f "%Lp" $key)
        if test $perms = "600"
            check_pass "$key_name has correct permissions (600)"
        else
            check_fail "$key_name has incorrect permissions ($perms). Should be 600"
        end
        
        # Check public key exists and has correct permissions
        if test -f "$key.pub"
            set perms (stat -f "%Lp" "$key.pub")
            if test $perms = "644"
                check_pass "$key_name.pub has correct permissions (644)"
            else
                check_warn "$key_name.pub has permissions $perms. Should be 644"
            end
        else
            check_warn "$key_name.pub not found"
        end
    end
end

if test $found_keys -eq 0
    check_warn "No ED25519 keys found. Generate with: ssh-keygen -t ed25519 -a 100"
end

# Check 6: Known hosts
if test -f ~/.ssh/known_hosts
    check_pass "~/.ssh/known_hosts exists"
    set perms (stat -f "%Lp" ~/.ssh/known_hosts)
    if test $perms = "600"
        check_pass "~/.ssh/known_hosts has correct permissions (600)"
    else
        check_warn "~/.ssh/known_hosts has permissions $perms. Should be 600"
    end
    
    # Check if hashed
    if grep -q '^|1|' ~/.ssh/known_hosts
        check_pass "known_hosts entries are hashed (HashKnownHosts enabled)"
    else
        check_warn "known_hosts entries not hashed. This will happen after first connection."
    end
else
    check_warn "~/.ssh/known_hosts does not exist yet (normal for new installation)"
end

# Check 7: Keys in SSH agent
print_header "5. SSH Agent"
set -l agent_keys (ssh-add -l 2>/dev/null | wc -l)
if test $agent_keys -gt 0
    check_pass "$agent_keys key(s) loaded in SSH agent"
    ssh-add -l
else
    check_warn "No keys in SSH agent. Add with: ssh-add --apple-use-keychain ~/.ssh/github_ed25519"
end

# Check 8: Critical security settings
print_header "6. Critical Security Settings"

# IdentitiesOnly
if ssh -G github.com | grep -q "identitiesonly yes"
    check_pass "IdentitiesOnly is enabled"
else
    check_fail "IdentitiesOnly is not enabled"
end

# PasswordAuthentication
if ssh -G github.com | grep -q "passwordauthentication no"
    check_pass "PasswordAuthentication is disabled"
else
    check_fail "PasswordAuthentication is not disabled"
end

# ForwardAgent
if ssh -G github.com | grep -q "forwardagent no"
    check_pass "ForwardAgent is disabled (secure default)"
else
    check_warn "ForwardAgent is enabled (security risk)"
end

# RekeyLimit
if ssh -G github.com | grep -q "rekeylimit"
    check_pass "RekeyLimit is configured"
else
    check_warn "RekeyLimit is not configured"
end

# Check 9: Crypto algorithms
print_header "7. Cryptographic Algorithms"
echo "Key Exchange:"
ssh -G github.com | grep "^kexalgorithms" | sed 's/kexalgorithms /  /'
echo ""
echo "Ciphers:"
ssh -G github.com | grep "^ciphers" | sed 's/ciphers /  /'
echo ""
echo "MACs:"
ssh -G github.com | grep "^macs" | sed 's/macs /  /'

# Check 10: GitHub connection test
print_header "8. GitHub Connection Test"
echo "Testing SSH connection to GitHub..."
if ssh -T git@github.com 2>&1 | grep -q "successfully authenticated"
    check_pass "Successfully authenticated to GitHub"
else
    check_warn "GitHub authentication test failed or key not added"
    echo "Run: ssh -T git@github.com"
end

print_header "Verification Complete"
echo "Review any warnings or failures above."
echo ""
echo "Next steps if needed:"
echo "  - Generate keys: ssh-keygen -t ed25519 -a 100 -f ~/.ssh/github_ed25519"
echo "  - Add to agent: ssh-add --apple-use-keychain ~/.ssh/github_ed25519"
echo "  - Copy public key: cat ~/.ssh/github_ed25519.pub | pbcopy"
echo "  - Add to GitHub: https://github.com/settings/keys"
echo ""
