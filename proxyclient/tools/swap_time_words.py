"""Which words of the swap_submit payload are 24 MHz time stamps, and what swap time each one matches.

  python3 swap_time_words.py ring.txt [--tag 194A] [--period 2048 --len 128]   (ring.txt from dump_s2r_ring.py)
  python3 swap_time_words.py --selftest

Input is the ring's big-call records (kind 4, one per call) and big-word records (kind 5, a changed word).
s2r_dcp_pkt.c records every changed word during the first --len calls of each --period calls (a window), and
the first call of a window records every non-zero word. So a window is forward-filled from its own first call
and no state crosses a window edge. An older ring (no windows) is read as one window: --period 1000000000
--len N, N = the call where the first busy word hit the churn limit.

For each 4-byte aligned offset that tracks the ring clock (u64 slope 0.95 to 1.05 over the window) the table gives
  lead      median of (word - reference word) in ms, reference = the tracking word with the least jitter
            (the submit time as the guest reads it; the guest clock is the ring clock plus one constant)
  b, a      least-squares fit  word - reference = a + b * interval, interval = this swap minus the previous swap
  match     b near 0: fixed lead (submit / update start); b near -1: the previous swap; b near -1/8: submit minus
            interval/8 (the announce target); b near +1: the next swap; else "other"
A window whose interval never varies cannot tell the b classes apart; the tool says so.
"""
import collections, gzip, re, statistics, sys

HZ = 24e6
CALL = re.compile(r"t=([0-9a-f]+) \+[0-9.]+s c\d+ PKT dcp(\d+) big-call w0 0x[0-9a-f]+ = 0x[0-9a-f]+ tag='?(\w+)'? in=0x[0-9a-f]+ slot=(\d+)")
WORD = re.compile(r"PKT dcp(\d+) big-word s(\d+) w(\d+) 0x[0-9a-f]+ = 0x([0-9a-f]+)")


def parse(lines, tag, dcp=0):
    """-> (ticks per call, changed words per call as [(word index, value)])."""
    ticks, changes, slot = [], [], None
    for l in lines:
        m = CALL.search(l)
        if m and int(m[2]) == dcp and m[3] == tag:
            slot = int(m[4])
            ticks.append(int(m[1], 16))
            changes.append([])
            continue
        m = WORD.search(l)
        if m and slot is not None and int(m[1]) == dcp and int(m[2]) == slot:
            changes[-1].append((int(m[3]), int(m[4], 16)))
    return ticks, changes


def windows(n, period, length, phase=0):
    return [(s, min(s + length, n)) for s in range(phase, n, period)]


def u32(words, off):
    w, r = divmod(off + 12, 8)
    return (words.get(w, 0) >> (8 * r)) & 0xFFFFFFFF if r in (0, 4) else None


def fit(xs, ys):
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return None
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sxx
    a = my - b * mx
    return a, b, statistics.pstdev([y - a - b * x for x, y in zip(xs, ys)])


def classify(b):
    for want, name in ((0, "fixed lead (submit / update start)"), (-1, "previous swap"), (-1 / 8, "submit - interval/8 (announce target)"),
                       (1, "next swap")):
        if abs(b - want) < 0.06:
            return name
    return "other"


def analyse_window(ticks, changes, lo, hi):
    """Time-word rows for calls lo..hi-1, or []. Calls need a previous swap, so lo+1 on."""
    words, per_call = {}, []
    for n in range(lo, hi):
        if n == lo:
            words = {}
        words.update(changes[n])
        per_call.append(dict(words))
    rows = []
    cn = range(lo + 1, hi)
    interval = [ticks[n] - ticks[n - 1] for n in cn]
    maxoff = (max((w for c in per_call for w in c), default=0)) * 8
    series = {}
    for off in range(0, maxoff, 4):
        v = []
        for n in cn:
            a, b = u32(per_call[n - lo], off), u32(per_call[n - lo], off + 4)
            if a is None or b is None:
                break
            v.append(a | b << 32)
        else:
            if len(set(v)) >= 8:
                dt = ticks[hi - 1] - ticks[lo + 1]
                slope = (v[-1] - v[0]) / dt if dt else 0
                if 0.95 < slope < 1.05:
                    series[off] = v
    if not series:
        return rows
    ref = min(series, key=lambda o: statistics.pstdev([x - ticks[n] for x, n in zip(series[o], cn)]))
    for off, v in sorted(series.items()):
        d = [(x - r) / HZ * 1000 for x, r in zip(v, series[ref])]
        f = fit([i / HZ * 1000 for i in interval], d)
        rows.append((off, statistics.median(d), f, off == ref))
    return rows


def report(ticks, changes, period, length, out=print, phase=0):
    found = 0
    for lo, hi in windows(len(ticks), period, length, phase):
        if hi - lo < 16:
            continue
        rows = analyse_window(ticks, changes, lo, hi)
        if not rows:
            out(f"calls {lo}..{hi - 1}: no word tracks the 24 MHz clock")
            continue
        found += 1
        out(f"calls {lo}..{hi - 1}: {len(rows)} time words; reference = the one marked *")
        for off, lead, f, is_ref in rows:
            if f is None:
                out(f"  +0x{off:x}{'*' if is_ref else ''}  lead {lead:+.3f} ms  interval constant in this window: b unknown")
            else:
                a, b, sd = f
                out(f"  +0x{off:x}{'*' if is_ref else ''}  lead {lead:+.3f} ms  a {a:+.3f} ms  b {b:+.3f}  resid sd {sd:.3f} ms  -> {classify(b)}")
    return found


def selftest():
    import random
    random.seed(7)
    t, ticks, ch = 10_000_000, [], []
    D0 = 123_456_789
    for n in range(300):
        interval = random.choice([2400, 3000, 8000, 20000, 100000])  # ticks
        t += interval
        ticks.append(t)
        w = {}
        w[50] = t + D0 & 0xFFFFFFFFFFFFFFFF                        # submit time, offset +0x184 (aligned to a word)
        w[60] = (t - interval) + D0                                # previous swap
        w[70] = t + D0 + 240 - interval // 8                       # announce target + 10 us
        w[80] = t + D0 + 3 * 24000                                 # fixed 3 ms lead
        w[90] = random.getrandbits(40)                             # not a time
        ch.append(sorted(w.items()))
    # windows of 128 calls every 150: forward fill resets at each window start
    rows = analyse_window(ticks, [dict_ for dict_ in ch], 0, 128)
    got = {off: classify(f[1]) for off, lead, f, ref in rows if f}
    want = {50 * 8 - 12: "fixed lead (submit / update start)", 60 * 8 - 12: "previous swap",
            70 * 8 - 12: "submit - interval/8 (announce target)", 80 * 8 - 12: "fixed lead (submit / update start)"}
    # the first window call has no previous swap here, so calls start at 1; the reference is the least-jitter word
    for off, name in want.items():
        assert got.get(off) == name, (hex(off), got.get(off), name)
    assert 90 * 8 - 12 not in got, "random word must not look like a time"
    print("selftest PASS:", {hex(o): n for o, n in sorted(got.items())})


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
        sys.exit(0)
    args = sys.argv[1:]
    opt = lambda name, d: type(d)(args[args.index(name) + 1]) if name in args else d
    path = args[0]
    tag, period, length = opt("--tag", "194A"), opt("--period", 2048), opt("--len", 128)
    # a ring that wrapped lost the oldest calls, so window starts are not multiples of the period: --phase -1 = first call with 100+ changed words
    phase = opt("--phase", -1)
    op = gzip.open if path.endswith(".gz") else open
    with op(path, "rt", errors="replace") as f:
        ticks, changes = parse(f, tag)
    if not ticks:
        sys.exit(f"no big-call records with tag {tag} on dcp0 in {path}")
    print(f"{len(ticks)} swap_submit calls, tag {tag}")
    if phase < 0:
        phase = next((i for i, c in enumerate(changes) if len(c) >= 100), 0) % period
    print(f"windows start at surviving call {phase}, then every {period}")
    if not report(ticks, changes, period, length, phase=phase):
        sys.exit("no window holds a time word")
