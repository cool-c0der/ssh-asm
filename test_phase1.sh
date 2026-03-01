#!/bin/bash
# Phase 1 test: version string exchange
set -e

BINARY=bin/ssh-asm
PORT=2222

echo "=== Phase 1 Test: SSH Version Exchange ==="

# Start server
$BINARY &
PID=$!
sleep 1

# Test version exchange
echo "Connecting to localhost:$PORT..."
RESPONSE=$(echo "SSH-2.0-TestClient_1.0" | nc -w 3 localhost $PORT 2>&1)

echo "Server response: '$RESPONSE'"

# Verify response
if echo "$RESPONSE" | grep -q "SSH-2.0-NasmSSH_1.0"; then
    echo "PASS: Server sent correct version string"
else
    echo "FAIL: Expected SSH-2.0-NasmSSH_1.0 in response"
    kill $PID 2>/dev/null
    exit 1
fi

# Cleanup
sleep 1
kill $PID 2>/dev/null
wait $PID 2>/dev/null || true
echo "=== Phase 1 Test PASSED ==="
