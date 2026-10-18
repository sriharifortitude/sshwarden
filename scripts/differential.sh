#!/usr/bin/env bash
# Compares sshwarden's reading of each fixture with a real sshd's. Needs sshd and sudo
# (sshd -T insists on its privilege-separation directory); CI installs openssh-server.
#   1. every value `sshwarden --effective` prints must equal what `sshd -T` prints;
#   2. `sshd -t` must reject exactly the fixtures sshwarden says sshd refuses to start on.
set -euo pipefail
cd "$(dirname "$0")/.."
SSHD=${SSHD:-/usr/sbin/sshd}
BIN=${SSHWARDEN:-./bin/sshwarden}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sudo mkdir -p /run/sshd
ssh-keygen -q -t ed25519 -N '' -f "$tmp/hostkey"
sudo "$SSHD" -T -f /dev/null -h "$tmp/hostkey" > "$tmp/defaults.txt"
"$SSHD" -V 2>&1 | head -1

# sshd resolves the Ubuntu fixture's absolute Include against the real /etc; point it at the copy.
sed "s|^Include /etc/ssh/sshd_config.d/\*.conf|Include $PWD/testdata/ubuntu/etc/ssh/sshd_config.d/*.conf|" \
  testdata/ubuntu/etc/ssh/sshd_config > "$tmp/ubuntu.conf"

compare() { # name, file for sshd, sshwarden arguments...
  local name=$1 for_sshd=$2; shift 2
  sudo "$SSHD" -T -f "$for_sshd" -h "$tmp/hostkey" > "$tmp/sshd.txt"
  "$BIN" --defaults "$tmp/defaults.txt" --effective "$@" > "$tmp/mine.txt"
  python3 - "$tmp/mine.txt" "$tmp/sshd.txt" "$name" <<'PY'
import sys
mine, real, name = sys.argv[1], sys.argv[2], sys.argv[3]
sshd = {}
for line in open(real):
    k, _, v = line.strip().partition(" ")
    sshd.setdefault(k, v.strip())
bad = 0
for line in open(mine):
    entry = line.split("\t#")[0].strip()
    k, _, v = entry.partition(" ")
    got = sshd.get(k)
    if got is None:
        print(f"{name}: sshd -T does not print {k}")
        bad += 1
    elif got.lower() != v.lower():
        print(f"{name}: {k}\n  sshwarden: {v}\n  sshd -T:   {got}")
        bad += 1
print(f"{name}: {sum(1 for _ in open(mine)) - bad} values agree, {bad} differ")
sys.exit(1 if bad else 0)
PY
}

status=0
compare stock /dev/null /dev/null || status=1
compare differential testdata/differential/sshd_config testdata/differential/sshd_config || status=1
compare hardened testdata/hardened/sshd_config testdata/hardened/sshd_config || status=1
compare ubuntu "$tmp/ubuntu.conf" --root testdata/ubuntu testdata/ubuntu/etc/ssh/sshd_config || status=1

# sshwarden's SSH040, SSH042 and SSH043 (high) mean "sshd refuses to start"; sshd -t must agree.
for f in testdata/hardened/sshd_config testdata/differential/sshd_config testdata/legacy/sshd_config "$tmp/ubuntu.conf"; do
  predicted=accept
  # sshwarden exits 1 when it has findings; under pipefail that must not decide the prediction.
  "$BIN" --json "$f" > "$tmp/findings.json" || true
  if python3 -c 'import json,sys; sys.exit(0 if any(x["id"] in ("SSH040","SSH042","SSH043") and x["severity"]=="high" for x in json.load(open(sys.argv[1]))["findings"]) else 1)' "$tmp/findings.json"; then
    predicted=reject
  fi
  if sudo "$SSHD" -t -f "$f" -h "$tmp/hostkey" 2>"$tmp/err.txt"; then actual=accept; else actual=reject; fi
  echo "$(basename "$(dirname "$f")")/$(basename "$f"): sshwarden predicts $predicted, sshd -t says $actual $(head -1 "$tmp/err.txt")"
  [ "$predicted" = "$actual" ] || status=1
done
exit $status
