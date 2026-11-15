#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read the S2R trace ring from a parked aura session and print every record, oldest first.

The ring (src/sptm_virt_s2r.c, struct s2r_rec) holds the guest's accesses to the hooked
coprocessor, PMGR and DART pages. Park the guest first, for example with
AURA_GPU_STOP_BOOT_SECS=<n> on run_guest_sptm.py, then run this from the aura tree whose
build/ holds the matching aura-raw.elf:

    python3 proxyclient/tools/dump_s2r_ring.py --out ring.txt [--pa 0x290600000:0x8000]
        [--val 0x28de94100] [--cpu 0] [--t0 TICKS]

Time is printed as raw CNTPCT ticks and as seconds from --t0 (default: the first record).
Every record is tagged with the ADT node and reg index that own its page, as <node[reg]+offset>
(the narrowest window when several overlap), and a per-node count follows the records.
"""
import argparse
import collections
import pathlib
import struct
import sys

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.append(str(pathlib.Path(__file__).resolve().parent))

REC = struct.Struct("<4Q")
CHUNK = 1 << 20
PKT_TAG = 0x544B5043  # "CPKT", the pc field of a DCP packet record
PKT_KINDS = {0: "AP-call", 1: "DCP-callback", 2: "AP-call-out", 3: "callback-out", 4: "big-call", 5: "big-word",
             6: "big-volatile", 7: "resolve"}
MARKER = 1 << 55
WRITE = 1 << 50
PKT_MAGIC = 0x0000315250523253  # "S2RPR1", src/s2r_dcp_pkt.h
PKT_WORDS = 528  # S2R_PKT_WORDS: holds the 4216-byte swap_submit packet (12 + 0x106c)
PKT_DCPS = 5  # S2R_DCP_N in src/s2r_dcp_pkt.c
PKT_HDR = struct.Struct("<4Q")  # magic, n (total calls ever), nent (entries), entry_bytes
PKT_ENTRY = struct.Struct(f"<2Q{PKT_WORDS}Q")  # call (0: unfinished), tick, the packet's words


def decode(rec):
    """One record: (t, pa, bits, write, cpu, marker, val, pc). cpu bits 5:4 are in meta[57:56]."""
    t, meta, val, pc = REC.unpack(rec)
    cpu = ((meta >> 51) & 15) | (((meta >> 56) & 3) << 4)
    return t, meta & ((1 << 48) - 1), 8 << ((meta >> 48) & 3), bool(meta & WRITE), cpu, bool(meta & MARKER), val, pc


def pkt_key(rec):
    """(dcp index, kind name) for the head of a packet record (word 0, or a resolve attempt); else None."""
    t, pa, bits, write, cpu, marker, val, pc = decode(rec)
    if marker or pc & 0xFFFFFFFF != PKT_TAG:
        return None
    kind, word = (pc >> 36) & 15, pc >> 40
    if kind not in (4, 6, 7) and word != 0:
        return None
    return (pc >> 32) & 15, PKT_KINDS.get(kind, f"kind{kind}")


def val_matches(val, wanted):
    """A value, or an address as its page number (>> 12) or its low 32 bits."""
    return any(val in (w, w >> 12, w & 0xFFFFFFFF) for w in wanted)


def owner(lookup, pa):
    """(<node[reg]+offset>, node[reg]) of the narrowest ADT window holding pa."""
    hits = lookup.lookup_all(pa) if lookup else []
    if not hits:
        return "<unmapped>", "unmapped"
    name, zone = min(hits, key=lambda h: h[1].stop - h[1].start)
    return f"<{name}+0x{pa - zone.start:x}>", name


def fmt(i, rec, t0, freq, lookup=None):
    t, pa, bits, write, cpu, marker, val, pc = decode(rec)
    secs = (t - t0) / freq
    if marker:
        return f"S2R {i} t={t:x} +{secs:.6f}s c{cpu} MARK {pc.to_bytes(8, 'little').rstrip(bytes(1)).decode('latin1')} 0x{val:x}"
    if pc & 0xFFFFFFFF == PKT_TAG:  # s2r_dcp_pkt.c: a DCP call's packet word, or a resolve attempt
        idx, kind, word = (pc >> 32) & 15, (pc >> 36) & 15, pc >> 40
        what = PKT_KINDS.get(kind, f"kind{kind}")
        extra, slot = "", ""
        if kind < 4 and word == 0:  # packet head: 4 tag characters, then the input size
            tag4 = bytes((val >> (8 * k)) & 255 for k in range(3, -1, -1))  # the wire holds the tag reversed
            extra = f" tag={tag4.decode('ascii', 'replace')!r} in={val >> 32}"
        if kind == 4:  # an AP call with a large input; word = its slot (15: none left), val = size << 32 | tag
            tag4 = bytes((val >> (8 * k)) & 255 for k in range(3, -1, -1))  # the wire holds the tag reversed
            extra = f" tag={tag4.decode('ascii', 'replace')!r} in=0x{val >> 32:x} slot={word}"
            word = 0
        elif kind in (5, 6):  # word w of the packet in slot s; the input starts at byte 12
            slot, word = f"s{word >> 12} ", word & 0xFFF
            extra = f" poff=0x{word * 8 - 12:x}"
            if kind == 6:
                extra += f" changed {val} times, not recorded again"
        if kind == 7:
            extra = f" found={val >> 32} refused={val & 0xFFFFFFFF} stream={word}"
        return f"S2R {i} t={t:x} +{secs:.6f}s c{cpu} PKT dcp{idx} {what} {slot}w{word} 0x{pa:x} = 0x{val:x}{extra}"
    tag = owner(lookup, pa)[0] if lookup else ""
    return f"S2R {i} t={t:x} +{secs:.6f}s c{cpu} {'W' if write else 'R'}{bits} 0x{pa:x} {tag} = 0x{val:x} pc=0x{pc:x}"


def keep(rec, args):
    t, pa, bits, write, cpu, marker, val, pc = decode(rec)
    if marker:
        return True
    if args.pa and not any(lo <= pa < lo + size for lo, size in args.pa):
        return False
    if args.cpu is not None and cpu != args.cpu:
        return False
    if args.val and not val_matches(val, args.val):
        return False
    return True


def parse_pa(text):
    lo, _, size = text.partition(":")
    return int(lo, 0), int(size, 0) if size else 1


def ring_entries(raw):
    """[(call, tick, packet words)] oldest first, from the bytes of struct s2r_pkt_ring (src/s2r_dcp_pkt.h).

    An entry the copy did not finish has call number 0 and is left out."""
    magic, n, nent, entry_bytes = PKT_HDR.unpack_from(raw)
    if magic != PKT_MAGIC or entry_bytes != PKT_ENTRY.size:
        raise SystemExit(f"packet ring: bad header (magic {magic:#x}, entry_bytes {entry_bytes})")
    out = []
    for i in range(nent):
        call, tick, *words = PKT_ENTRY.unpack_from(raw, PKT_HDR.size + i * entry_bytes)
        if call:
            out.append((call, tick, struct.pack(f"<{PKT_WORDS}Q", *words)))
    return sorted(out)


def pkt_bytes(entries):
    """A .pkts file's bytes: per entry a 16-byte header (call, tick) then the 4224 packet bytes, oldest first."""
    return b"".join(struct.pack("<2Q", call, tick) + data for call, tick, data in entries)


def read_ring(iface, ptr):
    """The whole ring of one DCP from the heap, in chunks."""
    magic, n, nent, entry_bytes = PKT_HDR.unpack(iface.readmem(ptr, PKT_HDR.size))
    raw = bytearray(iface.readmem(ptr, PKT_HDR.size))
    per = max(1, (1 << 20) // entry_bytes)
    for done in range(0, nent, per):
        k = min(per, nent - done)
        raw += iface.readmem(ptr + PKT_HDR.size + done * entry_bytes, k * entry_bytes)
    return bytes(raw), n


def write_pkts(iface, p, sym, prefix):
    """Read the packet ring of every DCP from the heap and write each one's kept calls to PREFIX-dcp<N>.pkts."""
    table = sym["sptm_virt_s2r_hist"]
    for idx in range(PKT_DCPS):
        ptr = p.read64(table + 8 * idx)
        if not ptr:
            continue
        raw, n = read_ring(iface, ptr)
        entries = ring_entries(raw)
        if not entries:
            print(f"pkts dcp{idx}: no finished call", file=sys.stderr)
            continue
        calls = [c for c, _, _ in entries]
        path = pathlib.Path(f"{prefix}-dcp{idx}.pkts")
        path.write_bytes(pkt_bytes(entries))
        print(f"pkts dcp{idx}: {len(entries)} of {n} calls kept, calls {calls[0]}..{calls[-1]}, "
              f"ticks {entries[0][1]}..{entries[-1][1]} -> {path}", file=sys.stderr)


def selftest():
    """The layout parser on a synthetic ring: two whole calls and one unfinished, oldest first."""
    wire = b"194A" + struct.pack("<II", 0x106C, 8) + bytes((k % 251) for k in range(0x106C))
    raw = struct.pack("<4Q", PKT_MAGIC, 2, 3, PKT_ENTRY.size)
    raw += struct.pack("<2Q", 1, 240_000_000) + wire.ljust(PKT_WORDS * 8, b"\0")
    raw += struct.pack("<2Q", 2, 264_000_000) + wire.ljust(PKT_WORDS * 8, b"\0")
    raw += struct.pack("<2Q", 0, 0) + bytes(PKT_WORDS * 8)  # the copy did not finish
    got = ring_entries(raw)
    assert [c for c, _, _ in got] == [1, 2]
    assert got[0][2][:12] == wire[:12] and got[0][2] == wire.ljust(PKT_WORDS * 8, b"\0")
    assert pkt_bytes(got)[:24] == struct.pack("<2Q", 1, 240_000_000) + wire[:8]
    print("selftest PASS: 2 calls of 3 kept, oldest first, packets whole")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--elf", type=pathlib.Path, default=pathlib.Path("build/aura-raw.elf"))
    ap.add_argument("--nm", default="llvm-nm")
    ap.add_argument("--out", type=pathlib.Path, help="write here instead of stdout")
    ap.add_argument("--pa", type=parse_pa, action="append", help="base[:size]; records inside only (repeatable)")
    ap.add_argument("--val", type=lambda v: int(v, 0), action="append", help="records with this value (repeatable)")
    ap.add_argument("--cpu", type=int)
    ap.add_argument("--t0", type=lambda v: int(v, 0), help="CNTPCT ticks for +0 s (default: first record)")
    ap.add_argument("--freq", type=int, default=24_000_000, help="CNTFRQ_EL0 (default 24 MHz)")
    ap.add_argument("--no-names", action="store_true", help="skip the ADT node lookup")
    ap.add_argument("--last", type=int, help="only the last N records in the ring")
    ap.add_argument("--hist", type=pathlib.Path, metavar="PREFIX",
                    help="write the packet ring (every large call, whole) of each DCP to PREFIX-dcp<N>.pkts")
    ap.add_argument("--hist-only", action="store_true", help="with --hist: skip the ring")
    ap.add_argument("--selftest", action="store_true", help="run the packet-ring parser selftest and exit")
    args = ap.parse_args()
    if args.selftest:
        selftest()
        return

    from run_guest_sptm import Symbols
    from aura.proxy import AuraProxy, UartInterface
    from aura.proxyutils import ProxyUtils, bootstrap_port

    iface = UartInterface()
    p = AuraProxy(iface, debug=False)
    bootstrap_port(iface, p)
    sym = Symbols(args.nm, args.elf, p.get_base())
    if args.hist:
        write_pkts(iface, p, sym, args.hist)
        if args.hist_only:
            return
    lookup = None if args.no_names else ProxyUtils(p).adt.build_addr_lookup()

    ring = p.read64(sym["sptm_virt_s2r_ring"])
    nrec = p.read64(sym["sptm_virt_s2r_nrec"])
    head = p.read64(sym["sptm_virt_s2r_head"])
    if not ring or not nrec:
        raise SystemExit("no S2R ring: aura was not run with AURA_S2R_TRACE=1")
    have = min(head, nrec)
    if args.last:
        have = min(have, args.last)
    first = head - have
    print(f"ring 0x{ring:x}, {nrec} records, head {head}: reading {have} (records {first}..{head - 1})",
          file=sys.stderr)

    out = open(args.out, "w") if args.out else sys.stdout
    t0, freq = args.t0, args.freq
    per = CHUNK // REC.size
    done = 0
    per_node = collections.Counter()
    per_pkt = collections.Counter()
    while done < have:
        n = min(per, have - done)
        i0 = (first + done) % nrec
        n = min(n, nrec - i0)  # one contiguous run; the ring wraps at nrec
        data = iface.readmem(ring + i0 * REC.size, n * REC.size)
        for k in range(n):
            rec = data[k * REC.size:(k + 1) * REC.size]
            if t0 is None:
                t0 = decode(rec)[0]
            if keep(rec, args):
                print(fmt(first + done + k, rec, t0, freq, lookup), file=out)
                if pkt_key(rec):
                    per_pkt[pkt_key(rec)] += 1
                if lookup and not decode(rec)[5] and decode(rec)[7] & 0xFFFFFFFF != PKT_TAG:
                    per_node[owner(lookup, decode(rec)[1])[1]] += 1
        done += n
    for name, count in per_node.most_common():
        print(f"NODE {name} {count}", file=out)
    for (idx, kind), count in sorted(per_pkt.items()):
        print(f"PKT dcp{idx} {kind} {count}", file=out)
    if args.out:
        out.close()
        print(f"wrote {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
