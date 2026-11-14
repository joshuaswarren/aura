/* SPDX-License-Identifier: MIT */

#ifndef S2R_DCP_PKT_H
#define S2R_DCP_PKT_H

#include "types.h"

extern u32 sptm_virt_s2r_dcp_pkt;

#define S2R_HIST_WORDS 1536
#define S2R_HIST_N     3
/*
 * The last S2R_HIST_N large calls (swap_submit) of a DCP, whole: word 0 and 1 of the packet, then the
 * words from the third on, volatile ones too. Call number c is at index (c - 1) % S2R_HIST_N; n is the
 * number of such calls so far and call[i] the number held at i (0: none, or the copy did not finish).
 * The ring keeps changed words only, and not a word that changed over 200 times; this keeps the payload.
 * A parked proxy reads it from the heap through sptm_virt_s2r_hist[dcp index].
 */
struct s2r_hist {
    u64 n;
    u64 call[S2R_HIST_N];
    u64 w[S2R_HIST_N][S2R_HIST_WORDS];
};
extern struct s2r_hist *sptm_virt_s2r_hist[];

void s2r_dcp_add(const char *name, u64 mbox);
void s2r_dcp_watch(u64 addr, const u64 *val, int width);
/* sptm_virt_s2r.c: one ring record with a caller's tag in its pc field. */
void sptm_virt_s2r_rec_raw(u64 pa, u64 val, u64 tag, bool write);

#endif
