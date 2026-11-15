"""The EDR fields of the swap_submit payload, one row per change, from the ring of a macOS swap trace.

  python3 swap_edr_words.py ring.txt [--tag 194A] [--dcp 0]   (ring.txt from dump_s2r_ring.py)
  python3 swap_edr_words.py --selftest

s2r_dcp_pkt.c records the words that hold bl_flags (0x358), bl_limit (0x376), edr_scale (0x37e, binary64) and
edr_headroom (0x3e6) at every change, so this tool forward-fills them from the first call and prints a row
whenever one changes. The offsets are read at two bases, because the base of the quoted offsets is not known:
  payload  the offset counts from the payload (the packet's first input byte; file offset = payload + 12)
  packet   the offset counts from the packet start
A row is: call number, seconds since the first call, then both readings. An older ring (before the EDR words were
watched) holds these words only up to the churn limit, so the tool warns when a field changed 200 times.
"""
import argparse, gzip, math, struct, sys

import swap_time_words as stw

FIELDS = (("bl_flags", 0x358, "<I"), ("bl_limit", 0x376, "<H"), ("edr_scale", 0x37E, "<d"), ("edr_headroom", 0x3E6, "<H"))


def read(words, off, fmt):
    """The field at byte `off` of the packet, from a {word index: u64} dict; None when a word is missing."""
    size = struct.calcsize(fmt)
    first, last = off // 8, (off + size - 1) // 8
    if any(w not in words for w in range(first, last + 1)):
        return None
    raw = b"".join(words[w].to_bytes(8, "little") for w in range(first, last + 1))
    return struct.unpack_from(fmt, raw, off - first * 8)[0]


def rows(ticks, changes):
    """-> [(call, seconds, {(base, field): value})] for every call where a field changed, and the first call."""
    words, out, last = {}, [], None
    for n, (t, ch) in enumerate(zip(ticks, changes)):
        words.update(ch)
        cur = {}
        for base, shift in (("payload", 12), ("packet", 0)):
            for name, off, fmt in FIELDS:
                cur[(base, name)] = read(words, off + shift, fmt)
        if cur != last:
            out.append((n, (t - ticks[0]) / stw.HZ, cur))
            last = cur
    return out


def fmt(v):
    if v is None:
        return "-"
    return f"{v:.6g}" if isinstance(v, float) else f"{v:#x}"


def show(out, ticks):
    for base in ("payload", "packet"):
        print(f"== offsets from the {base}")
        print("call      sec   " + "  ".join(f"{n:>14}" for n, _, _ in FIELDS))
        for n, sec, cur in out:
            print(f"{n:>5} {sec:8.3f}   " + "  ".join(f"{fmt(cur[(base, name)]):>14}" for name, _, _ in FIELDS))
    print(f"{len(ticks)} calls, {len(out)} rows")


def selftest():
    ticks = [int(24e6 * 0.0024 * i) for i in range(400)]
    changes = [[] for _ in ticks]
    raw, prev = bytearray(8 * 0x80), bytes(8 * 0x80)
    for i in range(400):
        struct.pack_into("<d", raw, 0x37E + 12, 1.2 + (16.0 - 1.2) * min(1, max(0, (i - 100) / 200)))
        struct.pack_into("<I", raw, 0x358 + 12, 7 if i >= 100 else 1)
        struct.pack_into("<H", raw, 0x3E6 + 12, 0x40 if i >= 100 else 0)
        for w in (0x6C, 0x71, 0x72, 0x7E):
            if raw[8 * w : 8 * w + 8] != prev[8 * w : 8 * w + 8] or i == 0:
                changes[i].append((w, int.from_bytes(raw[8 * w : 8 * w + 8], "little")))
        prev = bytes(raw)
    out = rows(ticks, changes)
    final = out[-1][2]
    assert final[("payload", "edr_scale")] == 16.0, final
    assert final[("payload", "bl_flags")] == 7 and final[("payload", "edr_headroom")] == 0x40, final
    assert out[0][2][("payload", "edr_scale")] == 1.2, out[0]
    assert 150 < len(out) < 220, len(out)
    print("selftest ok")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ring", nargs="?")
    ap.add_argument("--tag", default="194A")
    ap.add_argument("--dcp", type=int, default=0)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    opener = gzip.open if a.ring.endswith(".gz") else open
    with opener(a.ring, "rt") as f:
        ticks, changes = stw.parse(f, a.tag, a.dcp)
    out = rows(ticks, changes)
    show(out, ticks)


if __name__ == "__main__":
    sys.exit(main())
