#!/usr/bin/env bash
# Every store the management API exposes must be driven by the broker.
#
# An endpoint backed by a store that nothing outside crates/broker-api ever
# writes or reads answers 200 and means nothing: the ban list that no
# connect consults, the alarm set that no condition raises, the time series
# that nothing samples. Those compile, pass clippy and pass their own unit
# tests, so nothing else catches them.
#
# Each store is declared in tools/wiring.txt as one of:
#   wired  <field>              the broker must reference it
#   facade <field> <ticket>     known to be unwired, tracked by that ticket
#
# A store in neither list fails the check, so adding one forces the author
# to state which it is.
set -u
root=$(git rev-parse --show-toplevel)
decl="$root/tools/wiring.txt"
state="$root/crates/broker-api/src/lib.rs"
fail=0

fields=$(grep -oE "pub [a-z_]+: Arc<crate::v5::" "$state" | sed 's/pub //; s/: Arc<crate::v5:://' | sort -u)
for f in $fields; do
  line=$(grep -E "^(wired|facade)[[:space:]]+$f([[:space:]]|$)" "$decl" 2>/dev/null | head -1)
  users=$(git grep -l "\.$f" -- crates ':!crates/broker-api' 2>/dev/null | tr '\n' ' ')
  if [ -z "$line" ]; then
    echo "WIRING: '$f' is not declared in tools/wiring.txt (wired or facade)"
    fail=1
    continue
  fi
  case "$line" in
    wired*)
      if [ -z "$users" ]; then
        echo "WIRING: '$f' is declared wired, but nothing outside crates/broker-api uses it"
        fail=1
      fi ;;
    facade*)
      if [ -n "$users" ]; then
        echo "WIRING: '$f' is declared a facade but is now used by $users- move it to wired"
        fail=1
      fi ;;
  esac
done

if [ "$fail" = 0 ]; then echo "WIRING_OK"; fi
exit "$fail"
