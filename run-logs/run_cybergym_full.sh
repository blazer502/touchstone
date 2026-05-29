#!/usr/bin/env bash
cd /home/chanyoung/veri-agent
export PYTHONPATH=/home/chanyoung/veri-agent
export CYBERGYM_DATA_DIR=/mnt/data/chanyoung/cybergym/cybergym_data/data
export CYBERGYM_SERVER_DATA_DIR=/mnt/data/chanyoung/cybergym/cybergym-server-data
python3 eval/cybergym/run_level1.py \
  --subset eval/cybergym/subset-survived.json \
  --workers 24 \
  --libfuzzer-seconds 20 --libfuzzer-budget-max 60 --bank-budget 12 \
  --oss-fuzz-corpus \
  --denominator 1507 \
  --out run-logs/l1-full-postrecovery.json \
  --label full-postrecovery-1441
