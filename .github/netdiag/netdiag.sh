#!/bin/bash
# netdiag (ARK-25): where do the 14 s / 29 s idle stretches of an Nx replay from cache.outrun.sh come
# from on outrun-linux-arm64? DNS and TCP/TLS connects to cache.outrun.sh and turbo-cache.arkadia.so,
# with curl and with Bun's fetch, and the kernel's TCP/UDP counters around each part.
# Env: BUN_ACTION (the action's Bun 1.4.4), BUN_SETUP (setup-bun's), OIDC (the job's token for cache.outrun.sh).
set -u
here=$(cd "$(dirname "$0")" && pwd)
out=${RUNNER_TEMP:-/tmp}/netdiag
mkdir -p "$out"
HOSTS="cache.outrun.sh turbo-cache.arkadia.so"
path="/v8/artifacts/nxnetdiag0000?slug=netdiag"
FMT='%{time_namelookup} %{time_connect} %{time_appconnect} %{time_total} %{remote_ip} %{http_code}\n'

counters() { # name: TCP/UDP counters of interest, one "key value" per line
  { awk '/^Tcp:/ { if (!h) { split($0, k); h=1 } else { for (i=2;i<=NF;i++) print "Tcp" k[i], $i } }' /proc/net/snmp
    awk '/^Udp:/ { if (!u) { split($0, k); u=1 } else { for (i=2;i<=NF;i++) print "Udp" k[i], $i } }' /proc/net/snmp
    awk '/^TcpExt:/ { if (!x) { split($0, k); x=1 } else { for (i=2;i<=NF;i++) print "TcpExt" k[i], $i } }' /proc/net/netstat
    awk '/^Tcp6|^Udp6/ { print $1, $2 }' /proc/net/snmp6
  } | grep -E 'TcpRetransSegs|TcpActiveOpens|TcpAttemptFails|TcpEstabResets|TcpOutRsts|TcpExtTCPSynRetrans|TcpExtTCPTimeouts|TcpExtTCPLostRetransmit|TcpExtTCPAbortOnTimeout|TcpExtListenDrops|UdpInDatagrams|UdpOutDatagrams|UdpInErrors|UdpNoPorts|UdpRcvbufErrors|Udp6InDatagrams|Udp6OutDatagrams|Udp6InErrors|Udp6NoPorts' > "$out/c-$1"
}
delta() { # a b: counters that moved between snapshot a and b
  join "$out/c-$1" "$out/c-$2" | awk -v t="$1→$2" '{ if ($3 != $2) s = s sprintf(" %s=+%d", $1, $3 - $2) } END { print "COUNTERS " t ":" s }'
}
summ() { # label file: curl rows → counts
  awk -v l="$1" '{ n++; dns=$1; con=$2-$1; tls=$3-$2; tot=$4
      if (dns>1) d1++; if (con>1) c1++; if (tls>1) t1++; if (tot>1) o1++; if (tot>5) o5++
      if (dns>md) md=dns; if (con>mc) mc=con; if (tot>mt) mt=tot
      if ($5 ~ /:/) v6++; else v4++; st[$6]++ }
    END { s=""; for (k in st) s = s k "=" st[k] " "
      printf "SUMMARY %-34s n=%d dns>1s=%d connect>1s=%d tls>1s=%d total>1s=%d total>5s=%d max dns=%.2f connect=%.2f total=%.2f v4=%d v6=%d %s\n", l, n, d1, c1, t1, o1, o5, md, mc, mt, v4, v6, s }' "$2"
}

echo "::group::machine"
uname -a; cat /etc/resolv.conf; resolvectl status 2>/dev/null | head -40; ip -br addr; ip route; ip -6 route
echo "::endgroup::"
counters start
ss -s

echo "== 1. DNS =="
command -v dig >/dev/null || { sudo apt-get install -y -qq bind9-dnsutils >/dev/null 2>&1 || echo "no dig"; }
for h in $HOSTS; do
  for t in A AAAA; do
    for r in "" @1.1.1.1 @8.8.8.8 @1.0.0.1 @8.8.4.4; do
      times=$(for i in $(seq 10); do dig $r +tries=1 +time=20 "$h" "$t" | awk '/Query time/ { print $4 }'; done | tr '\n' ' ')
      echo "dig $h $t ${r:-system}: ms [$times] answer: $(dig $r +short "$h" "$t" | tr '\n' ' ')"
    done
  done
  ms=$( { for i in $(seq 50); do s=$(date +%s%N); getent ahosts "$h" >/dev/null; echo $(( ($(date +%s%N) - s) / 1000000 )); done; } | sort -n | awk '{ a[NR]=$1; if ($1>1000) s++ } END { printf "p50=%d max=%d n>1000ms=%d", a[int(NR/2)+1], a[NR], s }')
  echo "getent ahosts $h x50: $ms"
done
echo "IPv6: $(curl -6 -sS -o /dev/null -w '%{remote_ip} %{time_connect}s %{http_code}' --max-time 20 https://cache.outrun.sh/ 2>&1)"
ping -6 -c 3 -W 3 2606:4700:4700::1111 | tail -2
ping -4 -c 3 -W 3 1.1.1.1 | tail -2
counters dns; delta start dns

echo "== 2. curl, a new connection each request =="
for h in $HOSTS; do
  for fam in any -4 -6; do
    f="$out/curl-$h$fam-seq"; : > "$f"
    for i in $(seq 300); do curl ${fam#any} -s -o /dev/null --max-time 60 -w "$FMT" -H "Authorization: Bearer x" "https://$h$path" >> "$f"; done
    summ "curl $h ${fam} seq" "$f"
    f="$out/curl-$h$fam-par8"
    seq 300 | xargs -P 8 -I{} curl ${fam#any} -s -o /dev/null --max-time 60 -w "$FMT" -H "Authorization: Bearer x" "https://$h$path" > "$f"
    summ "curl $h ${fam} par8" "$f"
  done
done
counters curl; delta dns curl
for f in "$out"/curl-*; do awk -v f="${f##*/}" '$4>1 { print "SLOW", f, $0 }' "$f"; done

echo "== 3. Bun fetch =="
for b in "$BUN_ACTION" "$BUN_SETUP"; do
  echo "bun $b: $("$b" --revision)"
  for h in $HOSTS; do
    for mode in fresh pooled; do
      for c in 1 8; do
        "$b" "$here/fetch.ts" "https://$h$path" $mode $c 300 > "$out/bun-$h-$mode-$c" 2>&1
        echo "$h $mode c=$c: $(grep SUMMARY "$out/bun-$h-$mode-$c")"
        awk -v f="$h-$mode-$c" '$2>1000 { print "SLOW", f, $0 }' "$out/bun-$h-$mode-$c" | head -20
      done
    done
  done
done
counters bun; delta curl bun

echo "== 4. Bun 1.4.4 (action), pooled, 10 workers each pausing 0-2 s between requests, for 150 s, the job's OIDC token on cache.outrun.sh (404s through the access decision), no token on turbo-cache =="
PACE_MS=2000 "$BUN_ACTION" "$here/fetch.ts" "https://cache.outrun.sh$path" pooled 10 150s "$OIDC" > "$out/bunlong-outrun" 2>&1 &
PACE_MS=2000 "$BUN_ACTION" "$here/fetch.ts" "https://turbo-cache.arkadia.so$path" pooled 10 150s > "$out/bunlong-turbo" 2>&1 &
wait
for f in "$out"/bunlong-*; do echo "${f##*/}: $(grep SUMMARY "$f")"; awk -v f="${f##*/}" '$2>1000 { print "SLOW", f, $0 }' "$f" | head -30; done
counters long; delta bun long

echo "== 5. outrun nx-cache (the action's CLI) on 127.0.0.1:7070, 600 unknown hashes, 10 at a time =="
nohup outrun nx-cache --port 7070 > "$out/nx-cache.log" 2>&1 &
pid=$!
for i in $(seq 50); do curl -s -o /dev/null http://127.0.0.1:7070/v1/cache/0 && break; sleep 0.2; done
seq 600 | xargs -P 10 -I{} sh -c 'curl -s -o /dev/null --max-time 130 -w "$(date +%s.%N) %{time_total} %{http_code}\n" http://127.0.0.1:7070/v1/cache/netdiag$(date +%N){}' > "$out/nx-local"
kill $pid
awk '{ n++; if ($2>1) s1++; if ($2>5) s5++; if ($2>m) m=$2; st[$3]++ } END { for (k in st) s = s k "=" st[k] " "; printf "SUMMARY nx-cache local n=%d >1s=%d >5s=%d max=%.2f %s\n", n, s1, s5, m, s }' "$out/nx-local"
awk '$2>1 { print "SLOW nx-local", $0 }' "$out/nx-local" | head -30
tail -5 "$out/nx-cache.log"
counters end; delta long end; delta start end
ss -s
nstat -az 2>/dev/null | grep -E 'Retrans|Timeout|SynRetrans|InErrors|NoPorts' | head -20
