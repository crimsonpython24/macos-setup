function _tide_item_context
    set -l user_short (string sub -l 2 -- $USER)
    set -l host_short (string sub -l 3 -- (hostname -s))
    set -l ctx "$user_short@$host_short"
    
    if set -q SSH_TTY
        set -g tide_context_color $tide_context_color_ssh
    else if test "$USER" = root
        set -g tide_context_color $tide_context_color_root
    else if test "$tide_context_always_display" = true
        set -g tide_context_color $tide_context_color_default
    else
        return
    end
    
    _tide_print_item context $ctx
end
