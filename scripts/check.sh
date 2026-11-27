#!/usr/bin/env bash
# Runs every listing that can run without a phone, a database or the full Murmur server,
# and checks that every Go program builds. Used by CI; run it locally from the repo root.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
fail=0; pass=0
run() {  # run DIR CMD...   (prints one line per check)
  local dir=$1; shift
  if (cd "$dir" && timeout 300 "$@" >/tmp/murmur-check.log 2>&1); then
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
unset PYTHONPATH
for f in der_to_raw_test device_store; do run ch28code/client python3 "$f.py"; done
run ch31code/redteam python3 mitm_proxy.py
for f in pq_inventory pq_sizes; do run ch32code python3 "$f.py"; done

echo "== Appendix C: regenerate the test vectors; output must match the book exactly"
run appendix-c sh -c "python3 gen_vectors.py | diff - expected_output.txt"   # byte-identical to the book

echo "== Go: every program directory must build and pass go vet"
# Directories that need code the book describes but does not print (see README, "Known gaps").
SKIP="./ch14code/lab ./ch14code/library ./ch27code/server ./ch28code/server ./ch29code/server ./ch30code/server"
for d in $(find . -name go.mod -printf '%h\n' | sort); do
  case " $SKIP " in *" $d "*) echo "skip  $d (incomplete in the manuscript)"; continue;; esac
  run "$d" go vet .
  grep -lq 'go:build serve' "$d"/*.go 2>/dev/null && run "$d" go vet -tags serve .
done

echo
echo "passed: $pass   failed: $fail"
[ "$fail" -eq 0 ]
