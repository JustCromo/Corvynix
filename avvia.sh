#!/usr/bin/env bash
# Avvia cloud (porta 8002) e capsula (porta 8001). Ctrl+C li ferma entrambi.
cd "$(dirname "$0")"
source .venv/bin/activate
uvicorn cloud:app --port 8002 --log-level warning &
CLOUD_PID=$!
sleep 1
uvicorn capsule:app --port 8001 --log-level warning &
CAP_PID=$!
trap "kill $CLOUD_PID $CAP_PID 2>/dev/null" EXIT
echo ""
echo "  Corvynix"
echo ""
echo "  Pannello capsula:  http://127.0.0.1:8001"
echo "  Dashboard cloud:   http://127.0.0.1:8002
  Analisi dei voli:  http://127.0.0.1:8002/analisi"
echo ""
wait
