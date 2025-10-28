#!/bin/bash
# spdm-test-setup.sh

# Create tmux session with 3 equal windows
tmux new-session -d -s spdm-test -n responder
tmux new-window -t spdm-test:1 -n monitor
tmux new-window -t spdm-test:2 -n test

# Set up commands in each window
tmux send-keys -t spdm-test:responder 'cd app/ast1060-spdm-responder' Enter
tmux send-keys -t spdm-test:monitor 'echo "Ready for: sudo mctp monitor"' Enter  
tmux send-keys -t spdm-test:test 'cd app/ast1060-spdm-responder' Enter

# Split windows equally (choose one):
# Horizontal split (side by side)
tmux select-layout -t spdm-test even-horizontal

# OR Vertical split (stacked)
# tmux select-layout -t spdm-test even-vertical

# Attach to session
tmux attach-session -t spdm-test