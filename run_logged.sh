#!/bin/bash
# يشغّل الإطار ويسجّل كل شي بملف evidence تلقائيًا
set -e
STAMP=$(date +%Y%m%d_%H%M%S)
LOGFILE="evidence/raw_logs/run_${STAMP}.log"
echo "Logging to $LOGFILE"
python3 -m engine.main 2>&1 | tee "$LOGFILE"
