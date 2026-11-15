"""What the whole swap_submit packets say across the guest's SDR -> HDR -> SDR phases.

  python3 swap_pkts.py swap-dcp0.pkts
  python3 swap_pkts.py swap-dcp0.pkts --edges edges.txt --anchor 1790000000000=1000000000
  python3 swap_pkts.py --selftest

Input is PREFIX-dcpN.pkts from dump_s2r_ring.py --hist: per call a 16-byte header (call number, tick) then
the packet's 528 words (w[0]=h0: tag, input size; w[1]=h1; the input from byte 12 on the wire). The tick is
CNTPCT_EL0 (24 MHz), the same clock the ring records use. Fields are printed at both bases w86 uses: from
the packet start (0x358, 0x376, 0x37e, 0x3e6) and from the payload (0x34c, 0x36a, 0x372, 0x3da).

Per file it prints (a) one row per call with those fields; (b) per tag, which 4-byte-aligned payload offsets
changed between consecutive calls, top 40; (c) with --edges (lines EPOCH_MS LABEL, edr-sequence.sh) and
--anchor EPOCH_MS=TICK to put the ticks on the wall clock, per phase the offsets whose value is constant
inside the phase but differs from the previous phase - the fields a phase switch moves and holds.
Tags are grouped: 194A and 494A are different messages and must not be compared to each other.
"""
import argparse
import collections
import struct
import sys

HZ = 24_000_000
ENTRY = struct.Struct("<2Q528Q")  # call, tick, the packet's words (src/s2r_dcp_pkt.h)
FIELDS = (0x358, 0x376, 0x37E, 0x3E6), (0x34C, 0x36A, 0x372, 0x3DA)


def entries(path):
    """[(call, tick, the 4224 packet bytes)] in file order (oldest first)."""
    raw = open(path, "rb").read()
    if len(raw) % ENTRY.size:
        sys.exit(f"{path}: {len(raw)} bytes is not whole {ENTRY.size}-byte entries")
    return [(e[0], e[1], struct.pack("<528Q", *e[2:])) for e in ENTRY.iter_unpack(raw)]


def tag(data):
    """The tag as the ring prints it: the wire holds the tag's characters reversed ('194A' is A491)."""
    return data[3::-1].decode("ascii", "replace")


def inp(data):
    return int.from_bytes(data[4:8], "little")  # h0 >> 32


def field(data, off, base=12):
    """The 32-bit value at off from the payload (base 12) or from the packet start (base 0), or None past the input."""
    p = off + base
    return int.from_bytes(data[p:p + 4], "little") if p + 4 <= min(inp(data) + 12, len(data)) else None


def rows(entries):
    """(a) one line per call: number, seconds from the first call, tag, the fields at both bases."""
    t0 = entries[0][1]
    out = []
    for call, tick, data in entries:
        secs = (tick - t0) / HZ
        vals = " ".join(f"+0x{o:x}={field(data, o, base):#010x}" if field(data, o, base) is not None else f"+0x{o:x}=-"
                        for (base, offs) in zip((0, 12), FIELDS) for o in offs)
        out.append(f"call {call} +{secs:.6f}s tag {tag(data)} {vals}")
    return out


def histogram(entries):
    """(b) per tag: {payload offset: calls where it changed} between consecutive calls of the same tag."""
    by_tag = collections.defaultdict(list)
    for call, tick, data in entries:
        by_tag[tag(data)].append(data)
    out = {}
    for tg, datas in by_tag.items():
        c = collections.Counter()
        for a, b in zip(datas, datas[1:]):
            for off in range(0, min(inp(a), inp(b)), 4):
                if field(a, off) != field(b, off):
                    c[off] += 1
        out[tg] = c
    return out


def read_edges(path):
    """[(epoch_ms, label)] from lines EPOCH_MS LABEL."""
    edges = []
    for l in open(path):
        ms, _, label = l.partition(" ")
        if ms.strip():
            edges.append((int(ms, 0), label.strip() or "?"))
    return sorted(edges)


def phases(entries, edges, anchor):
    """(c) per tag, per phase: the offsets constant inside the phase whose value differs from the previous phase.

    anchor = EPOCH_MS=TICK puts the ticks on the wall clock; a phase starts at each edge."""
    epoch0, tick0 = anchor
    out = {}
    for tg in sorted({tag(d) for _, _, d in entries}):
        es = [(c, t, d) for c, t, d in entries if tag(d) == tg]
        if len(es) < 2:
            continue
        groups, idx = [], None
        for call, tick, data in es:
            ms = epoch0 + (tick - tick0) * 1000 / HZ
            i = max((j for j, (e, _) in enumerate(edges) if e <= ms), default=-1)
            if i != idx:
                groups.append((edges[i][1] if i >= 0 else "before", []))
                idx = i
            groups[-1][1].append(data)
        found = []
        for (label_prev, prev), (label, now) in zip(groups, groups[1:]):
            step = {}
            for off in range(0, min(min(inp(d) for d in prev + now), 4224 - 12), 4):
                vp = {field(d, off) for d in prev}
                vn = {field(d, off) for d in now}
                if len(vp) == len(vn) == 1 and vp != vn:
                    step[off] = (vn.pop(), vp.pop())
            if step:
                found.append((label, label_prev, len(now), len(prev), step))
        out[tg] = found
    return out


def selftest():
    """Synthetic packets: a time word, a field the HDR phase moves and holds, a random word, a second tag."""
    import random
    random.seed(7)
    base = 1_000_000_000
    t, ent = base, []
    for n in range(30):
        t += random.choice([2400, 3000, 8000, 20000])
        w = {0: 0x31393441 | 0x106C << 32, 50: t + 123_456_789, 90: random.getrandbits(48),
             0x6B: 5 if n < 10 else 7 if n < 20 else 5}
        ent.append((n + 1, t, b"".join(w.get(i, 0).to_bytes(8, "little") for i in range(528))))

    r = rows(ent)
    assert r[0].startswith("call 1 +0.000000s tag 194A ") and r[1].startswith("call 2 +")
    assert "+0x358=0x00000005" in r[5] and "+0x34c=0x00000005" in r[5]  # 0x358 from the packet start and 0x34c from the payload are the same field

    h = histogram(ent)
    tg = tag(ent[0][2])
    assert h[tg][0x184] == 29 and h[tg][0x34C] == 2 and h[tg][0x2C4] == 29

    # a second tag lands in its own histogram and phase groups, never compared to 194A
    for n in range(3):
        w = {0: 0x34393441 | 0x40 << 32, 0x6B: 9}
        ent.append((100 + n, ent[-1][1] + 3000, b"".join(w.get(i, 0).to_bytes(8, "little") for i in range(528))))
    assert set(histogram(ent)) == {tg, "494A"}

    # edges at the calls where the field moves and holds: calls 11 and 21
    at = lambda k: base * 1000 + (ent[k][1] - ent[0][1]) * 1000 / HZ
    edges = [(at(10), "HDR"), (at(20), "SDR-2")]
    p = phases(ent, edges, (base * 1000, ent[0][1]))
    flips = [(off, val) for _, _, _, _, s in p[tg] for off, val in s.items()]
    assert [off for off, _ in flips] == [0x34C, 0x34C], flips
    assert flips[0][1] == (7, 5) and flips[1][1] == (5, 7), flips
    print(f"selftest PASS: tag {tg}, fields at both bases, histogram 29/2 changes, phase flips 0x34c 5->7->5")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pkts", help="PREFIX-dcpN.pkts from dump_s2r_ring.py --hist")
    ap.add_argument("--edges", help="file of EPOCH_MS LABEL lines (edr-sequence.sh)")
    ap.add_argument("--anchor", help="EPOCH_MS=TICK: which tick the wall clock read at that epoch")
    a = ap.parse_args()
    ent = entries(a.pkts)
    if not ent:
        sys.exit(f"{a.pkts}: no entry")
    print("\n".join(rows(ent)))
    for tg, c in histogram(ent).items():
        n = len([e for e in ent if tag(e[2]) == tg])
        print(f"\ntag {tg}: {n} calls; words that changed between consecutive calls, top 40 of {len(c)}")
        for off, k in c.most_common(40):
            print(f"  +0x{off:x}  {k}/{n - 1}")
    if a.edges or a.anchor:
        if not (a.edges and a.anchor):
            sys.exit("--edges and --anchor go together")
        ms, _, tk = a.anchor.partition("=")
        for tg, found in phases(ent, read_edges(a.edges), (int(ms, 0), int(tk, 0))).items():
            print(f"\ntag {tg} phases:")
            for label, label_prev, n_now, n_prev, step in found:
                print(f"  {label} ({n_now} calls) vs {label_prev} ({n_prev}): {len(step)} fields moved and held")
                for off in sorted(step):
                    v, o = step[off]
                    print(f"    +0x{off:x} = {v:#010x} (was {o:#010x} in {label_prev})")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
        sys.exit(0)
    main()
