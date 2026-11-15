# SPDX-License-Identifier: MIT
"""dump_s2r_ring.py turns the aura heap's packet ring (every large DCP call, whole) into .pkts files."""
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "proxyclient/tools"))
import dump_s2r_ring  # noqa: E402

WORDS = dump_s2r_ring.PKT_WORDS


def packet(tag, in_bytes, payload):
    """The on-wire packet: tag (4), input size (4), output size (4), then the input from byte 12."""
    return tag + struct.pack("<II", in_bytes, 8) + payload


def entry(call, tick, wire):
    """One ring entry's bytes: the packet padded to what the heap entry holds."""
    return struct.pack("<2Q", call, tick) + wire.ljust(WORDS * 8, b"\0")


def ring(nent, n, entries):
    """The bytes of struct s2r_pkt_ring: header, then nent entries; entries[i] = (call, tick, wire bytes)."""
    raw = struct.pack("<4Q", dump_s2r_ring.PKT_MAGIC, n, nent, dump_s2r_ring.PKT_ENTRY.size)
    for i in range(nent):
        call, tick, wire = entries.get(i, (0, 0, b""))
        raw += entry(call, tick, wire)
    return raw


def test_the_entry_is_16_header_bytes_plus_528_packet_words():
    assert dump_s2r_ring.PKT_HDR.size == 32
    assert dump_s2r_ring.PKT_ENTRY.size == 16 + WORDS * 8 == 4240
    assert WORDS * 8 >= 12 + 0x106C  # the swap_submit packet fits


def test_calls_come_out_oldest_first_with_all_their_bytes():
    wires = [packet(b"194A", 0x106C, bytes((i + 1) * 16 + (k % 7) for k in range(0x106C))) for i in range(3)]
    raw = ring(3, 252, {i: (250 + i, 1000 + i, wires[i]) for i in range(3)})
    got = dump_s2r_ring.ring_entries(raw)
    assert [c for c, _, _ in got] == [250, 251, 252]
    for (call, tick, data), want in zip(got, wires):
        assert tick == 1000 + call - 250
        assert data == want.ljust(WORDS * 8, b"\0"), f"call {call}"


def test_entries_are_ordered_by_call_not_by_slot():
    p = packet(b"194A", 8, bytes(8))
    raw = ring(3, 5, {0: (4, 40, p), 1: (5, 50, p), 2: (3, 30, p)})  # call 3 is at (3 - 1) % 3 == 2
    assert [c for c, _, _ in dump_s2r_ring.ring_entries(raw)] == [3, 4, 5]


def test_an_unfinished_or_never_used_entry_is_left_out():
    p = packet(b"194A", 8, bytes(8))
    raw = ring(3, 1, {0: (1, 10, p)})
    got = dump_s2r_ring.ring_entries(raw)
    assert [c for c, _, _ in got] == [1]
    assert dump_s2r_ring.ring_entries(ring(3, 0, {})) == []


def test_a_bad_header_is_refused():
    raw = struct.pack("<4Q", 0, 0, 3, dump_s2r_ring.PKT_ENTRY.size)
    try:
        dump_s2r_ring.ring_entries(raw)
    except SystemExit as e:
        assert "magic" in str(e)
    else:
        raise AssertionError("bad magic accepted")


def test_the_pkts_file_is_16_byte_headers_plus_whole_packets_oldest_first():
    p = packet(b"494A", 16, bytes(range(16)))
    raw = ring(3, 5, {0: (4, 40, p), 1: (5, 50, p), 2: (3, 30, p)})
    got = dump_s2r_ring.ring_entries(raw)
    want = b"".join(struct.pack("<2Q", c, t) + d for c, t, d in got)
    assert dump_s2r_ring.pkt_bytes(got) == want
    assert len(want) == 3 * (16 + WORDS * 8)
