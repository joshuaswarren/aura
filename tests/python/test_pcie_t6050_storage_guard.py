# SPDX-License-Identifier: GPL-2.0-only
"""The T6050 storage guard lets auto-PM move a storage power domain, and nothing else.

iBoot leaves APCIE_SYS_ST0 with auto-PM on. When storage goes idle the hardware gates the domain
and rewrites ACTUAL and PS_AUTO. On 2026-11-14 that stopped two boots (0x280900150 0x1f0003ff ->
0x1000030f). Every other bit of a storage PS register must still stop the boot.
"""

import re
import subprocess
from pathlib import Path

from host_compiler import host_cc

REPO = Path(__file__).resolve().parents[2]


def moved_ok_source():
    source = (REPO / "src/pcie_t6050.c").read_text()
    match = re.search(r"^static bool storage_ps_moved_ok\(.*?^}\n", source, re.DOTALL | re.MULTILINE|re.DOTALL | re.MULTILINE)
    assert match, "storage_ps_moved_ok() is missing from src/pcie_t6050.c"
    return match.group(0)


def test_storage_ps_moved_ok(tmp_path):
    harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
typedef uint32_t u32;
#define BIT(n) (1U << (n))
#define GENMASK(h, l) (((~0U) >> (31 - (h))) & ((~0U) << (l)))
''' + moved_ok_source() + r'''
int main(void)
{
    const u32 active = 0x1f0003ff;
    /* the 2026-11-14 event: auto-PM gated an idle domain */
    assert(storage_ps_moved_ok(active, 0x1000030f));
    assert(storage_ps_moved_ok(active, active));
    /* ACTUAL and the was-gated flags move without auto-PM help, as before */
    assert(storage_ps_moved_ok(0x0000030f, 0x000003ff));
    assert(storage_ps_moved_ok(0x1f00030f, 0x1f0000ff));
    /* TARGET moved: somebody wrote the register */
    assert(!storage_ps_moved_ok(active, 0x1000030f ^ 0xf));
    assert(!storage_ps_moved_ok(active, 0x100003f0));
    /* auto-PM off, or turned off, or turned on: PS_AUTO is not the hardware's to change */
    assert(!storage_ps_moved_ok(0x0f0003ff, 0x0000030f));
    assert(!storage_ps_moved_ok(active, 0x0000030f));
    assert(!storage_ps_moved_ok(0x000003ff, 0x1000030f));
    /* every other bit still stops */
    for (int b = 0; b < 32; b++) {
        bool free_bit = (b >= 4 && b <= 9) || (b >= 24 && b <= 27);
        if (free_bit)
            continue;
        assert(!storage_ps_moved_ok(active, active ^ BIT(b)));
        assert(!storage_ps_moved_ok(active, 0x1000030f ^ BIT(b)));
    }
    return 0;
}
'''
    binary = tmp_path / "storage-guard"
    subprocess.run(
        [*host_cc(), "-std=c11", "-Wall", "-Wextra", "-Werror", "-x", "c", "-", "-o", str(binary)],
        input=harness, text=True, check=True,
    )
    subprocess.run([str(binary)], check=True)
