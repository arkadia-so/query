// netdiag (ARK-25): times GETs with Bun's fetch. Usage:
//   bun fetch.ts <url> <fresh|pooled> <concurrency> <count|"<n>s"> [token]
// fresh: keepalive false (a new connection each time); pooled: Bun's default connection pool.
// PACE_MS: each worker waits a random 0..PACE_MS ms between its requests (idle pooled connections).
// Prints one line per request ("start_ms dur_ms status", start relative to the first), then a summary.
const [url, mode, concArg, countArg, token] = process.argv.slice(2);
const conc = Number(concArg);
const byTime = countArg.endsWith("s");
const limit = byTime ? Number(countArg.slice(0, -1)) * 1000 : Number(countArg);
const pace = Number(process.env.PACE_MS ?? 0);
const t0 = performance.now();
const rows: [number, number, string][] = [];
let issued = 0;
const more = () => (byTime ? performance.now() - t0 < limit : issued < limit);
const worker = async () => {
  while (more()) {
    issued++;
    const s = performance.now();
    let status = "";
    try {
      const r = await fetch(url, {
        keepalive: mode === "pooled",
        headers: { authorization: `Bearer ${token || "x"}` },
        signal: AbortSignal.timeout(60_000),
      });
      await r.arrayBuffer();
      status = String(r.status);
    } catch (e) {
      status = `ERR:${e instanceof Error ? e.message.replace(/\s+/g, "_") : String(e)}`;
    }
    rows.push([s - t0, performance.now() - s, status]);
    if (pace > 0) await Bun.sleep(Math.random() * pace);
  }
};
await Promise.all(Array.from({ length: conc }, worker));
rows.sort((a, b) => a[0] - b[0]);
for (const [s, d, st] of rows) console.log(`${s.toFixed(1)} ${d.toFixed(1)} ${st}`);
const durs = rows.map((r) => r[1]).sort((a, b) => a - b);
const q = (p: number) => durs[Math.min(durs.length - 1, Math.floor(durs.length * p))].toFixed(0);
// Idle: the longest stretches with no request in flight.
const spans = rows.map(([s, d]) => [s, s + d]).sort((a, b) => a[0] - b[0]);
const idle: number[] = [];
let end = spans[0]?.[1] ?? 0;
for (const [s, e] of spans) {
  if (s > end) idle.push(s - end);
  end = Math.max(end, e);
}
idle.sort((a, b) => b - a);
const statuses: Record<string, number> = {};
for (const r of rows) statuses[r[2]] = (statuses[r[2]] ?? 0) + 1;
console.log(
  `SUMMARY bun=${Bun.version}+${Bun.revision.slice(0, 9)} ${mode} c=${conc} n=${rows.length} wall=${((performance.now() - t0) / 1000).toFixed(1)}s ` +
    `p50=${q(0.5)} p99=${q(0.99)} max=${durs.at(-1)?.toFixed(0)} ms >1s=${durs.filter((d) => d > 1000).length} >5s=${durs.filter((d) => d > 5000).length} ` +
    `idle>1s=${idle.filter((i) => i > 1000).length} idle_top=${idle
      .slice(0, 3)
      .map((i) => (i / 1000).toFixed(1))
      .join(",")}s statuses=${JSON.stringify(statuses)} dns=${JSON.stringify(Bun.dns.getCacheStats())}`,
);
