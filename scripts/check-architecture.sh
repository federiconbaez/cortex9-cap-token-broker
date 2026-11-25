#!/usr/bin/env bash
# The domain must not import crypto crates, encoding crates, I/O, time or outer layers.
set -euo pipefail
cd "$(dirname "$0")/.."
pattern='\b(hmac|sha2|subtle|getrandom|base64)::|std::(fs|net|io|time|thread|process|env)|crate::(adapters|application)'
if grep -rnE "$pattern" src/domain; then
  echo "architecture violation: src/domain must stay pure" >&2
  exit 1
fi
if grep -rnE '\b(hmac|sha2|subtle|getrandom|base64)::' src/application src/ports.rs; then
  echo "architecture violation: crypto/encoding crates only allowed in src/adapters" >&2
  exit 1
fi
echo "architecture OK"
