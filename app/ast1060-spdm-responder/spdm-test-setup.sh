#!/bin/bash
# spdm-test-setup.sh - Create tmux session with 3 equal panes

# Kill existing session if it exists
tmux kill-session -t spdm-test 2>/dev/null

# Create new session with one window
tmux new-session -d -s spdm-test -n testing

# Split window into 3 horizontal panes
tmux split-window -h -t spdm-test:testing    # Creates pane 1
tmux split-window -h -t spdm-test:testing.0  # Splits pane 0, creates pane 2

# Make panes equal size
tmux select-layout -t spdm-test:testing even-horizontal

# Set up each pane
tmux send-keys -t spdm-test:testing.0 'cd app/ast1060-spdm-responder && echo "Pane 0: SPDM Responder (run ./test-spdm.sh)"' Enter
tmux send-keys -t spdm-test:testing.1 'echo "Pane 1: MCTP Monitor (run: sudo mctp monitor)"' Enter  
tmux send-keys -t spdm-test:testing.2 'cd app/ast1060-spdm-responder && echo "Pane 2: Test Client (run: sudo ../../target/debug/test-spdm-request)"' Enter

# Select first pane
tmux select-pane -t spdm-test:testing.0

# Attach to session
tmux attach-session -t spdm-test