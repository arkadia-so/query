#!/bin/bash
# netdiag run 2 (ARK-25), job burst: do bursts of new connections lose SYNs, with curl alone (so the
# network) or only with Bun's fetch (which opens several sockets per connection)? Every test under
# one packet capture (SYNs, SYN-ACKs, RSTs on 443, ICMP), read by syn.py per test window.
set -u
here=$(cd "$(dirname "$0")" && pwd)
out=${RUNNER_TEMP:-/tmp}/netdiag
mkdir -p "$out"
path="/v8/artifacts/nxnetdiag0000?slug=netdiag"
FMT='%{time_namelookup} %{time_connect} %{time_appconnect} %{time_total} %{remote_ip} %{http_code}\n'
synretx() { awk '/^TcpExt:/ { if (!x) { split($0, k); x=1 } else for (i=2;i<=NF;i++) if (k[i]=="TCPSynRetrans") print $i }' /proc/net/netstat; }
command -v tcpdump >/dev/null || sudo apt-get install -y -qq tcpdump >/dev/null 2>&1 || echo "no tcpdump"
sudo tcpdump -i any -nn -s 96 -U -w "$out/burst.pcap" 'tcp port 443 or icmp or icmp6' 2> "$out/tcpdump.err" &
sleep 2
windows=()
run() { # label command...: runs it, prints SYN retransmits and the window
  local s e r0 r1
  r0=$(synretx); s=$(date +%s.%N)
  "${@:2}"
  e=$(date +%s.%N); r1=$(synretx)
  echo "TEST $1: $(awk -v s="$s" -v e="$e" 'BEGIN { printf "%.1f", e - s }') s, TCPSynRetrans +$((r1 - r0))"
  windows+=("$s" "$e" "$1")
  sleep 3
}
curls() { # fam par n host
  seq "$3" | xargs -P "$2" -I{} curl ${1#any} -s -o /dev/null --max-time 60 -w "$FMT" -H "Authorization: Bearer x" "https://$4$path" > "$out/curl-$4-$1-$2"
  awk -v l="curl $4 $1 P$2" '{ n++; c=$2-$1; if (c>1) c1++; if ($4>1) o1++; if (c>mc) mc=c; if ($5 ~ /:/) v6++; else v4++ } END { printf "  %s: n=%d connect>1s=%d total>1s=%d max connect=%.2f v4=%d v6=%d\n", l, n, c1, o1, mc, v4, v6 }' "$out/curl-$4-$1-$2"
}
buns() { # mode c n host
  "$BUN_ACTION" "$here/fetch.ts" "https://$4$path" "$1" "$2" "$3" > "$out/bun-$4-$1-$2" 2>&1
  echo "  $(grep SUMMARY "$out/bun-$4-$1-$2" | cut -c1-260)"
}
h=cache.outrun.sh
run "curl any P8" curls any 8 300 $h
run "curl any P32" curls any 32 600 $h
run "curl -4 P32" curls -4 32 600 $h
run "curl -6 P32" curls -6 32 600 $h
run "curl any P64" curls any 64 600 $h
run "bun fresh c1" buns fresh 1 100 $h
run "bun fresh c8" buns fresh 8 300 $h
run "bun fresh c32" buns fresh 32 600 $h
run "bun pooled c10 (cold pool)" buns pooled 10 300 $h
run "bun fresh c8 turbo-cache" buns fresh 8 300 turbo-cache.arkadia.so
# The same with one IPv4 address only: an /etc/hosts entry pins it.
ip4=$(getent ahostsv4 $h | awk 'NR==1 { print $1 }')
echo "$ip4 $h" | sudo tee -a /etc/hosts >/dev/null
run "bun fresh c8, one IPv4 address (/etc/hosts)" buns fresh 8 300 $h
run "bun fresh c32, one IPv4 address (/etc/hosts)" buns fresh 32 600 $h
run "curl any P32, one IPv4 address (/etc/hosts)" curls any 32 600 $h
sudo sed -i "/ $h\$/d" /etc/hosts
sleep 2
sudo pkill -INT tcpdump; sleep 2
cat "$out/tcpdump.err" | tail -3
tcpdump -nn -tt -r "$out/burst.pcap" 2>/dev/null | python3 "$here/syn.py" "${windows[@]}"
