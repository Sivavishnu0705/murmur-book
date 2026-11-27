#!/usr/bin/env bash
# Runs every listing that can run without a phone, a database or the full Murmur server,
# and checks that every Go program builds. Used by CI; run it locally from the repo root.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
fail=0; pass=0
run() {  # run DIR CMD...   (prints one line per check)
  local dir=$1; shift
  if (cd "$dir" && timeout 900 "$@" >/tmp/murmur-check.log 2>&1); then
    pass=$((pass+1)); echo "ok    $dir: $*"
  else
    fail=$((fail+1)); echo "FAIL  $dir: $*"; tail -5 /tmp/murmur-check.log | sed 's/^/      /'
  fi
}

echo "== protobuf schemas"
for s in ch26code ch27code ch29code; do run "$s/spec" python3 -m grpc_tools.protoc -I. --python_out=. murmur.proto; done

echo "== Volume 1 Python"
for f in listing-2.1 listing-2.2 listing-2.4 listing-2.6 listing-2.7 listing-2.9 envelope listing-2.13; do run ch2code python3 "$f.py"; done
run ch3code python3 check_threat_model.py murmur-threat-model.yaml
run ch5code python3 gen_bad_certs.py /tmp/murmur-cases
run ch4code python3 inspect_cert.py /tmp/murmur-cases/good.chain.pem
run ch4code openssl x509 -in cryptography-io-2018.pem -noout -text   # Listing 4.1
run ch8code python3 spki_pin.py /tmp/murmur-cases/good.chain.pem
run ch6code python3 tls13_key_schedule.py
run ch7code python3 listing-7.4.py
run ch10code python3 listing-10.3.py

echo "== Volume 2 Python"
for f in ake signed_dh triple_dh toys lab; do run ch16code python3 "$f.py"; done
for f in noise_min xx_lib pairing; do run ch17code python3 "$f.py"; done
for f in xeddsa x3dh pqxdh lab; do run ch18code python3 "$f.py"; done
for f in ratchet fuzz lab; do run ch19code python3 "$f.py"; done
for f in safety kt; do run ch20code python3 "$f.py"; done
run ch21code/attach python3 attachments.py
for f in senderkeys lab; do run ch22code python3 "$f.py"; done
export PYTHONPATH="$ROOT/ch18code:$ROOT/ch19code"
for f in check_spk_flaw buggy_ratchet find_bug lint_insecure; do run ch25code python3 "$f.py"; done
run ch25code python3 -m pytest -q -p no:cacheprovider test_ratchet_props.py
if command -v proverif >/dev/null; then          # Listing 25.3 (optional: needs ProVerif)
  run ch25code sh -c 'proverif x3dh.pv | grep -E "^RESULT"'
else
  echo "skip  ch25code: proverif x3dh.pv (ProVerif not installed)"
fi
unset PYTHONPATH
for f in der_to_raw_test device_store; do run ch28code/client python3 "$f.py"; done
run ch31code/redteam python3 mitm_proxy.py
for f in pq_inventory pq_sizes; do run ch32code python3 "$f.py"; done

echo "== Appendix C: regenerate the test vectors; output must match the book exactly"
run appendix-c sh -c "python3 gen_vectors.py | diff - expected_output.txt"   # byte-identical to the book

echo "== Go: every program directory must build and pass go vet"
for d in $(find . -name go.mod -not -path '*/target/*' -printf '%h\n' | sort); do
  # A module with external dependencies but no go.sum yet: resolve it (checksums verified
  # against sum.golang.org). Commit the resulting go.sum.
  if grep -q '^require' "$d/go.mod" && [ ! -f "$d/go.sum" ]; then run "$d" go mod tidy; fi
  run "$d" go vet .
  grep -lq 'go:build serve' "$d"/*.go 2>/dev/null && run "$d" go vet -tags serve .
  grep -lq 'go:build lab' "$d"/*.go 2>/dev/null && run "$d" go vet -tags lab .
done

echo "== Labs that need the Go server (Chapters 14, 27–29)"
BIN=$(mktemp -d)
run ch14code/lab go run .
run ch27code/server go run . -selftest
for c in 27 28 29; do run "ch${c}code/server" go build -o "$BIN/murmur-lab$c" .; done
run ch27code/lab python3 lab.py "$BIN/murmur-lab27"
run ch28code/client python3 lab.py "$BIN/murmur-lab28"
run ch29code/client python3 lab.py "$BIN/murmur-lab29"

echo "== Chapter 31: release build refuses to start; lab build has the malicious-server mode"
run ch31code/server sh -c "go build -o $BIN/murmur-server . && { $BIN/murmur-server; test \$? -eq 2; }"
run ch31code/server go build -tags lab -o "$BIN/murmur-lab31" .
run ch31code/rotation go run .

if command -v cargo >/dev/null 2>&1; then
  echo "== Rust: every crate builds; the Chapter 30 core drives the Chapter 30 lab and Chapter 31"
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
  for d in ch17code/murmur-core ch23code/ffi ch23code/mls_lab ch26code/core ch27code/mlsgen ch28code/core; do
    run "$d" cargo build --release --quiet
  done
  run ch30code/core sh -c "cargo build --release --quiet && cargo run --release --quiet --bin uniffi-bindgen -- \
    generate --library \"\$CARGO_TARGET_DIR/release/libmurmur_groups.so\" --language python --out-dir py \
    && cp \"\$CARGO_TARGET_DIR/release/libmurmur_groups.so\" py/"
  run ch30code/server go build -o "$BIN/murmur-lab30" .
  run ch30code/client python3 lab.py "$BIN/murmur-lab30"
  run ch31code/redteam python3 redteam.py "$BIN/murmur-lab31"
  # Release gate (Listing 31.3): the Chapter 30 tree is blocked; Chapter 31's fixes pass.
  run . sh -c "! python3 ch31code/release_gate.py ch30code/server ch29code/ios >/dev/null"
  run . sh -c "T=\$(mktemp -d) && cp ch29code/ios/NotificationService.swift \$T/ \
    && patch -s -d \$T NotificationService.swift < ch31code/listing-31.8.diff \
    && python3 ch31code/release_gate.py ch31code/server \$T"
else
  echo "skip  Rust crates, Chapter 30 lab and Chapter 31 red team (cargo not installed)"
fi

echo
echo "passed: $pass   failed: $fail"
[ "$fail" -eq 0 ]
