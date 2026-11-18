#!/bin/bash
# One take of the README/site demo: a real run, recorded from tmux.
#
# Before: a workspace with one locksql lock on a throwaway database
# (`lox add locksql`), and a tmux session `demo253` whose window `rec` has
# two panes of 79 and 92 columns, 42 rows: pane 0 a shell in the workspace
# (the agent goes there), pane 1 `lox run --manual` with the lock serving
# (console started with `lox attach` in another window). lox, the locksql
# launcher and the lock's image must be the same release.
#
#   bash take.sh take.jsonl          # types the question, approves in lox run
#   python3 render.py take.jsonl fr  # one PNG per screen + fr/concat.txt
#   ffmpeg -f concat -safe 0 -i fr/concat.txt -vf fps=25,format=yuv420p -c:v libx264 -crf 24 -movflags +faststart demo.mp4
#   ffmpeg -f concat -safe 0 -i fr/concat.txt -vf fps=25,format=yuv420p -c:v libvpx-vp9 -crf 36 -b:v 0 demo.webm
#   ffmpeg -f concat -safe 0 -i fr/concat.txt -vf "fps=10,scale=1400:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=64:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" demo.gif
#
# rec.py stores the panes' text, colours and timing; render.py draws them
# (DejaVu Sans Mono, the site's terminal colours) and blanks only the lines
# listed in its HIDE (notices of the recording machine).
cd "$(dirname "$0")"; L=demo253:rec.0; R=demo253:rec.1; out=${1:-take.jsonl}
left() { tmux capture-pane -t $L -p; }; right() { tmux capture-pane -t $R -p; }
idle() { ! left | grep -q 'esc to interrupt'; }
tmux send-keys -t $L "clear; claude --setting-sources project,local --model sonnet" Enter
for _ in $(seq 1 30); do left | grep -q 'auto mode on' && break; sleep 1; done; sleep 4
rm -f "$out.stop"; python3 rec.py "$out" & sleep 2.5
msg='In the dev database: our 3 Belgian customers with the highest total spend, with their name and email.'
for ((i=0;i<${#msg};i++)); do tmux send-keys -t $L -l "${msg:$i:1}"; sleep 0.045; done
sleep 0.9; tmux send-keys -t $L Enter
for _ in $(seq 1 90); do right | grep -q 'QUESTION read' && break; sleep 1; done
sleep 4.5; tmux send-keys -t $R d; sleep 5.5; tmux send-keys -t $R y; sleep 3
for _ in $(seq 1 60); do idle && break; sleep 1; done; sleep 2
if ! left | grep -q '<redacted> *│'; then   # the agent stopped at "pending": tell it the ticket is decided
  msg='Approved.'; for ((i=0;i<${#msg};i++)); do tmux send-keys -t $L -l "${msg:$i:1}"; sleep 0.08; done
  sleep 0.7; tmux send-keys -t $L Enter; sleep 3
fi
for _ in $(seq 1 90); do idle && break; sleep 1; done
sleep 6; touch "$out.stop"; wait; echo "take done: $(wc -l < "$out") screens"
