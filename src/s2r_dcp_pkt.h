/* SPDX-License-Identifier: MIT */

#ifndef S2R_DCP_PKT_H
#define S2R_DCP_PKT_H

#include "types.h"

extern u32 sptm_virt_s2r_dcp_pkt;

#define S2R_HIST_WORDS 1536 /* S2R_BIG_WORDS: the dense/EDR scan of the other big calls; unchanged */
#define S2R_PKT_WORDS  528 /* holds a whole swap_submit packet (12 + 0x106c = 4216 bytes) */
#define S2R_PKT_RING_MAGIC 0x0000315250523253ULL /* "S2RPR1" */
/*
 * Every large call of a DCP (swap_submit, tags A491 and A494) whole, in a ring that wraps: word 0 and 1 of
 * the packet, then the words from the third on, volatile ones too. Entry (call number n - 1) % nent holds
 * call n; call is 0 while the copy is unfinished, and the reader leaves such entries out. tick is
 * CNTPCT_EL0, the same clock the ring records' t= field uses. A parked proxy reads it from the heap through
 * sptm_virt_s2r_hist[dcp index] (the symbol keeps its name for the dump tool).
 */
struct s2r_pkt_entry {
    u64 call;
    u64 tick;
    u64 w[S2R_PKT_WORDS];
};
struct s2r_pkt_ring {
    u64 magic; /* S2R_PKT_RING_MAGIC */
    u64 n;     /* calls the ring has taken, total */
    u64 nent;  /* entries it holds */
    u64 entry_bytes;
    struct s2r_pkt_entry e[];
};
extern struct s2r_pkt_ring *sptm_virt_s2r_hist[];

void s2r_dcp_add(const char *name, u64 mbox);
void s2r_dcp_watch(u64 addr, const u64 *val, int width);
/* sptm_virt_s2r.c: one ring record with a caller's tag in its pc field. */
void sptm_virt_s2r_rec_raw(u64 pa, u64 val, u64 tag, bool write);

#endif
