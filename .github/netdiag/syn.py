#!/usr/bin/env python3
# netdiag (ARK-25): connection attempts and silences from `tcpdump -nn -tt -r <pcap> 'tcp port 443 or icmp or icmp6'`.
# Usage: tcpdump ... | syn.py [from_epoch to_epoch label]...   (windows to report apart; none = the whole capture)
# Reports, per window: attempts (a SYN's 4-tuple) by family, attempts whose SYN was sent again (and
# after how many SYNs they were answered), fan-outs (attempts started within 5 ms of each other,
# as Bun's fetch does for one connection) and how long until the first of them was answered, and
# every silence over 2 s with no packet on port 443, with the attempts pending during it.
import re, sys, collections

line_re = re.compile(r"^(\d+\.\d+) (?:\S+ +(?:In|Out|P|M) +)?(IP6?) (\S+)\.(\d+) > (\S+)\.(\d+): Flags \[([^\]]*)\]")
icmp_re = re.compile(r"^(\d+\.\d+) .*(ICMP6?|icmp6?)")
att = {}  # key -> dict
pkts = []  # times of port-443 packets
icmps = []
for line in sys.stdin:
    m = line_re.match(line)
    if not m:
        if icmp_re.match(line):
            icmps.append(line.strip()[:200])
        continue
    t, fam, src, sp, dst, dp, flags = float(m[1]), m[2], m[3], m[4], m[5], m[6], m[7]
    if dp != "443" and sp != "443":
        continue
    pkts.append(t)
    if dp == "443":
        key = (src, sp, dst)
        if flags == "S":
            a = att.setdefault(key, {"t": t, "syns": [], "fam": "v6" if fam == "IP6" else "v4", "dst": dst, "ack": None, "rst": None})
            a["syns"].append(t)
        elif "R" in flags and key in att and att[key]["rst"] is None:
            att[key]["rst"] = t
    elif flags == "S.":
        key = (dst, dp, src)
        if key in att and att[key]["ack"] is None:
            att[key]["ack"] = t

windows = [(float(sys.argv[i]), float(sys.argv[i + 1]), sys.argv[i + 2]) for i in range(1, len(sys.argv) - 2, 3)] or [(0, 1e12, "all")]
print(f"packets on 443: {len(pkts)}, attempts: {len(att)}, ICMP lines: {len(icmps)}")
for line in icmps[:10]:
    print("  ICMP", line)
for lo, hi, label in windows:
    A = sorted((a for a in att.values() if lo <= a["t"] < hi), key=lambda a: a["t"])
    if not A:
        print(f"[{label}] no attempts")
        continue
    fam = collections.Counter(a["fam"] for a in A)
    retx = [a for a in A if len(a["syns"]) > 1]
    by = collections.Counter((a["fam"], len(a["syns"]), "answered" if a["ack"] else "never") for a in retx)
    unanswered = sum(1 for a in A if not a["ack"])
    print(f"[{label}] attempts {dict(fam)}; SYN sent again: {len(retx)} ({dict(collections.Counter(a['fam'] for a in retx))}); never answered: {unanswered}")
    for (f, n, o), c in sorted(by.items()):
        print(f"    {f} {n} SYNs, {o}: {c}")
    # Fan-outs: attempts whose first SYN is within 5 ms of the previous one's.
    groups, cur = [], [A[0]]
    for a in A[1:]:
        if a["t"] - cur[-1]["t"] <= 0.005:
            cur.append(a)
        else:
            groups.append(cur)
            cur = [a]
    groups.append(cur)
    sizes = collections.Counter(len(g) for g in groups)
    delays = []
    for g in groups:
        acks = [a["ack"] for a in g if a["ack"]]
        delays.append((min(acks) - g[0]["t"]) if acks else None)
    slow = [d for d in delays if d is None or d > 1]
    print(f"    fan-outs: {len(groups)}, sizes {dict(sorted(sizes.items()))}; first answer > 1 s: {len(slow)} "
          f"(never: {sum(1 for d in delays if d is None)}); slowest: {sorted([round(d, 2) for d in delays if d is not None])[-5:]}")
    for g, d in zip(groups, delays):
        if d is None or d > 1:
            desc = ", ".join(f"{a['fam']} {a['dst']} {len(a['syns'])} SYNs {'ack +%.2fs' % (a['ack'] - a['syns'][0]) if a['ack'] else 'no ack'}" for a in g)
            print(f"      at +{g[0]['t'] - lo:.2f}s first answer {'never' if d is None else '%.2fs' % d}: {desc}")
    P = [t for t in pkts if lo <= t < hi]
    gaps = [(P[i], P[i + 1] - P[i]) for i in range(len(P) - 1) if P[i + 1] - P[i] > 2]
    print(f"    silences > 2 s on 443: {len(gaps)}, total {sum(g for _, g in gaps):.1f} s")
    for s, g in gaps:
        pend = [a for a in att.values() if a["t"] <= s + 0.001 and (a["ack"] or 1e12) > s and (a["rst"] or 1e12) > s]
        desc = "; ".join(f"{a['fam']} {a['dst']} SYNs at +{','.join('%.1f' % (x - a['t']) for x in a['syns'])}s {'ack +%.2fs' % (a['ack'] - a['t']) if a['ack'] else 'no ack'}" for a in pend[:8])
        print(f"      +{s - lo:.1f}s silent {g:.1f}s, pending attempts {len(pend)}: {desc}")
