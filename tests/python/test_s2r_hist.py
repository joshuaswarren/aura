# SPDX-License-Identifier: MIT
"""dump_s2r_ring.py turns the aura heap's struct s2r_hist (the last three large DCP calls, whole) into the packets."""
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "proxyclient/tools"))
import dump_s2r_ring  # noqa: E402

WORDS = 1536


def hist(n, calls, packets):
    """The bytes of struct s2r_hist: n, call[3], w[3][1536]. packets[i] is the packet at index i."""
    raw = struct.pack("<4Q", n, *calls)
    for i in range(3):
        raw += packets.get(i, b"").ljust(WORDS * 8, b"\0")
    return raw


def packet(tag, size, payload):
    """Tag (4 bytes), input size (4), 4 bytes that are not input, then the input from byte 12."""
    return tag + struct.pack("<I", size) + bytes(4) + payload


def test_the_struct_size_is_what_the_heap_holds():
    assert dump_s2r_ring.HIST.size == 8 * 4 + 3 * WORDS * 8


def test_three_consecutive_calls_come_out_oldest_first_with_all_their_bytes():
    packets = [packet(b"194A", 0x106C, bytes((i + 1) * 16 + (k % 7) for k in range(0x106C))) for i in range(3)]
    raw = hist(252, (250, 251, 252), dict(enumerate(packets)))
    got = dump_s2r_ring.hist_calls(raw)
    assert [c for c, _ in got] == [250, 251, 252]
    for (call, data), want in zip(got, packets):
        assert data == want, f"call {call}"
        assert len(data) == 12 + 0x106C


def test_calls_are_ordered_by_number_not_by_slot():
    p = [packet(b"194A", 8, bytes([i]) * 8) for i in range(3)]
    raw = hist(5, (4, 5, 3), dict(enumerate(p)))  # call 3 is at (3 - 1) % 3 == 2
    assert [c for c, _ in dump_s2r_ring.hist_calls(raw)] == [3, 4, 5]


def test_a_slot_that_did_not_finish_or_was_never_used_is_left_out():
    raw = hist(1, (1, 0, 0), {0: packet(b"194A", 8, bytes(8))})
    assert [c for c, _ in dump_s2r_ring.hist_calls(raw)] == [1]
    assert dump_s2r_ring.hist_calls(hist(0, (0, 0, 0), {})) == []


def test_a_size_larger_than_the_copy_holds_is_cut_to_what_was_kept():
    raw = hist(1, (1, 0, 0), {0: packet(b"XXXX", 0xFFFFFFF0, b"\1" * 64)})
    (call, data), = dump_s2r_ring.hist_calls(raw)
    assert len(data) == WORDS * 8
