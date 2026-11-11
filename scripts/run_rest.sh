#!/bin/sh
# Second half of the pipeline (latency + tau sensitivity), as used for the paper.
# Waits until the E3 experiment has finished, then runs the remaining steps. Run from anywhere.
cd "$(dirname "$0")/.." || exit 1
mkdir -p results/logs
until grep -q done results/logs/log_E3.txt 2>/dev/null; do sleep 10; done
python3 src/latency.py > results/logs/log_latency.txt 2>&1
for t in 0.4 0.8; do
  python3 src/build_graphs.py $t > results/logs/log_build_$t.txt 2>&1
  python3 src/experiment.py E1 --tau $t --only tbguard --tag _tau$t > results/logs/log_E1_tau$t.txt 2>&1
done
python3 src/tau_sens.py > results/logs/log_tau.txt 2>&1
echo ALLDONE >> results/logs/log_tau.txt
