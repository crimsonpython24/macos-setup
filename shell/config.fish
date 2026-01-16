if status is-interactive
# Commands to run in interactive sessions can go here
end
fzf_configure_bindings --directory=\cf --git_log=\cl --git_status=\cs --history=\cr --processes=\cp --variables=\cv
set -gx GPG_TTY (tty)


# Tide v6 prompt configuration
# powerlevel10k / tmux inspired theme - CRIMSON EDITION

# ─── Prompt Structure ───
set -g tide_prompt_add_newline_before false
set -g tide_prompt_pad_items true
set -g tide_prompt_min_cols 34
set -g tide_prompt_color_frame_and_connection 585858
set -g tide_prompt_color_separator_same_color 626262
set -g tide_prompt_transient_enabled false

# ─── Left Prompt ───
set -g tide_left_prompt_frame_enabled true
set -g tide_left_prompt_items status vi_mode context pwd git aws docker go java kubectl nix_shell node php private_mode rustc terraform toolbox python
set -g tide_left_prompt_prefix ''
set -g tide_left_prompt_suffix 

# ─── Right Prompt ───
set -g tide_right_prompt_frame_enabled true
set -g tide_right_prompt_items jobs time
set -g tide_right_prompt_prefix 
set -g tide_right_prompt_suffix ''

# ─── Status (exit code display) ───
set -g tide_status_bg_color 262626
set -g tide_status_bg_color_failure 262626
set -g tide_status_color FFD700
set -g tide_status_color_failure D70000
set -g tide_status_icon 0
set -g tide_status_icon_failure 

# ─── Vi Mode (distinctive warm shades per mode) ───
set -g tide_vi_mode_bg_color_default 3A3A3A
set -g tide_vi_mode_bg_color_insert 875F00
set -g tide_vi_mode_bg_color_replace 5F5F00
set -g tide_vi_mode_bg_color_visual 870087
set -g tide_vi_mode_color_default AF5F5F
set -g tide_vi_mode_color_insert FFAF5F
set -g tide_vi_mode_color_replace FFD787
set -g tide_vi_mode_color_visual FF87FF

# ─── Context (CRIMSON default, dark red root, magenta ssh) ───
set -g tide_context_always_display true
set -g tide_context_bg_color 303030
set -g tide_context_color_default FF5F5F
set -g tide_context_color_root AF0000
set -g tide_context_color_ssh FF5FFF
set -g tide_context_hostname_parts 1

# ─── PWD (gold anchors, coral dirs - high contrast) ───
set -g tide_pwd_bg_color 3A3A3A
set -g tide_pwd_color_anchors FFD700
set -g tide_pwd_color_dirs FF8700
set -g tide_pwd_color_truncated_dirs 626262
set -g tide_pwd_truncate_margin 80
set -g tide_pwd_markers .bzr .citc .git .hg .node-version .python-version .ruby-version .shorten_folder_marker .svn .terraform bun.lock Cargo.toml composer.json CVS go.mod package.json build.zig

# ─── Git (distinctive warm palette for each state) ───
set -g tide_git_bg_color 303030
set -g tide_git_bg_color_unstable 303030
set -g tide_git_bg_color_urgent 303030
set -g tide_git_color_branch FF8700
set -g tide_git_color_conflicted D70087
set -g tide_git_color_dirty FFAF00
set -g tide_git_color_operation FF005F
set -g tide_git_color_staged FFD75F
set -g tide_git_color_stash FFAFD7
set -g tide_git_color_untracked D787D7
set -g tide_git_color_upstream FF875F
set -g tide_git_truncation_length 24
set -g tide_git_truncation_strategy ''

# ─── Time (muted rose-gray) ───
set -g tide_time_bg_color normal
set -g tide_time_color 8A6B6B
set -g tide_time_format '%H:%M:%S'

# ─── Jobs (bright amber) ───
set -g tide_jobs_bg_color 262626
set -g tide_jobs_color FFAF00
set -g tide_jobs_number_threshold 1000

# ─── Private Mode (deep magenta) ───
set -g tide_private_mode_bg_color 5F005F
set -g tide_private_mode_color FF87FF

# ─── Tool-specific (each tool gets distinctive warm shade) ───
set -g tide_aws_bg_color 262626
set -g tide_aws_color FF8700
set -g tide_docker_bg_color 262626
set -g tide_docker_color AF87FF
set -g tide_docker_default_contexts default colima
set -g tide_go_bg_color 262626
set -g tide_go_color FFD787
set -g tide_java_bg_color 262626
set -g tide_java_color FF5F00
set -g tide_kubectl_bg_color 262626
set -g tide_kubectl_color AF5FD7
set -g tide_nix_shell_bg_color 262626
set -g tide_nix_shell_color D787D7
set -g tide_node_bg_color 262626
set -g tide_node_color D7AF5F
set -g tide_php_bg_color 262626
set -g tide_php_color D7AFD7
set -g tide_python_bg_color 262626
set -g tide_python_color FF87AF
set -g tide_rustc_bg_color 262626
set -g tide_rustc_color D75F00
set -g tide_terraform_bg_color 262626
set -g tide_terraform_color D75FD7
set -g tide_toolbox_bg_color 262626
set -g tide_toolbox_color FF5FAF
