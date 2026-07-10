#!/usr/bin/env python3
"""Diagnostic: check why call graph has no connections."""
import struct
from elftools.elf.elffile import ELFFile
from collections import defaultdict

VMLINUX = "/Users/xiuxiu391/Desktop/oppo/vmlinux.elf"

with open(VMLINUX, "rb") as f:
    elf = ELFFile(f)
    text = elf.get_section_by_name(".text")
    data = text.data()

print(f".text size: 0x{len(data):x}")

# Check a few BL instructions and their targets
bl_samples = []
for i in range(0x10000, min(len(data) - 3, 0x20000), 4):
    inst = struct.unpack_from("<I", data, i)[0]
    if (inst >> 26) == 0x25:
        imm26 = inst & 0x3FFFFFF
        if imm26 & 0x2000000:
            imm26 -= 0x4000000
        target = i + imm26 * 4
        bl_samples.append((i, target, imm26))
        if len(bl_samples) >= 20:
            break

print(f"\nSample BL instructions in [0x10000, 0x20000]:")
for caller, target, imm in bl_samples:
    # Check if target has a PACIASP
    has_paciasp = False
    if 0 <= target < len(data) - 3:
        tinst = struct.unpack_from("<I", data, target)[0]
        has_paciasp = (tinst == 0xD503233F)
    print(f"  BL at 0x{caller:06x} -> 0x{target:06x} (imm26={imm:#x}) {'[PACIASP]' if has_paciasp else '[no PACIASP]'}")

# Check: how many BL targets have PACIASP?
total_bl = 0
target_has_paciasp = 0
target_in_range = 0
for i in range(0x10000, len(data) - 3, 4):
    inst = struct.unpack_from("<I", data, i)[0]
    if (inst >> 26) == 0x25:
        total_bl += 1
        imm26 = inst & 0x3FFFFFF
        if imm26 & 0x2000000:
            imm26 -= 0x4000000
        target = i + imm26 * 4
        if 0 <= target < len(data) - 3:
            target_in_range += 1
            tinst = struct.unpack_from("<I", data, target)[0]
            if tinst == 0xD503233F:
                target_has_paciasp += 1

print(f"\nBL statistics:")
print(f"  Total BL in [0x10000, end]: {total_bl}")
print(f"  Target in range: {target_in_range}")
print(f"  Target has PACIASP: {target_has_paciasp}")

# Check: are there BL instructions with target = 0 (unresolved)?
zero_targets = 0
for i in range(0, len(data) - 3, 4):
    inst = struct.unpack_from("<I", data, i)[0]
    if (inst >> 26) == 0x25:
        imm26 = inst & 0x3FFFFFF
        if imm26 & 0x2000000:
            imm26 -= 0x4000000
        target = i + imm26 * 4
        if target == 0 or target == i:
            zero_targets += 1

print(f"  BL with target=0 or target=self: {zero_targets}")

# Now check: for the known futex functions at 0x07da1c (frame=0x1a0), 
# what BL instructions target them?
print(f"\nSearching for BL to 0x07da1c (potential futex_wait_requeue_pi)...")
xrefs_to_futex_pi = []
for i in range(0, len(data) - 3, 4):
    inst = struct.unpack_from("<I", data, i)[0]
    if (inst >> 26) == 0x25:
        imm26 = inst & 0x3FFFFFF
        if imm26 & 0x2000000:
            imm26 -= 0x4000000
        target = i + imm26 * 4
        if target == 0x07da1c:
            xrefs_to_futex_pi.append(i)

print(f"  Found {len(xrefs_to_futex_pi)} BL to 0x07da1c")
for off in xrefs_to_futex_pi[:10]:
    print(f"    BL at 0x{off:06x}")

# And for 0x07e178 (frame=0x1c0, potential do_futex)
print(f"\nSearching for BL to 0x07e178 (potential do_futex)...")
xrefs_to_do_futex = []
for i in range(0, len(data) - 3, 4):
    inst = struct.unpack_from("<I", data, i)[0]
    if (inst >> 26) == 0x25:
        imm26 = inst & 0x3FFFFFF
        if imm26 & 0x2000000:
            imm26 -= 0x4000000
        target = i + imm26 * 4
        if target == 0x07e178:
            xrefs_to_do_futex.append(i)

print(f"  Found {len(xrefs_to_do_futex)} BL to 0x07e178")
for off in xrefs_to_do_futex[:10]:
    # What function is this BL inside?
    print(f"    BL at 0x{off:06x}")

# Check: does the do_futex function call the futex_pi function?
print(f"\nChecking if 0x07e178 calls 0x07da1c...")
for i in range(0x07e178, 0x07e178 + 0x200, 4):
    if i + 3 >= len(data):
        break
    inst = struct.unpack_from("<I", data, i)[0]
    if (inst >> 26) == 0x25:
        imm26 = inst & 0x3FFFFFF
        if imm26 & 0x2000000:
            imm26 -= 0x4000000
        target = i + imm26 * 4
        print(f"    BL at 0x{i:06x} -> 0x{target:06x}")

# Check if 0x020c54 (frame=0x70, sys_futex) calls 0x07e178 (do_futex)
print(f"\nChecking if 0x020c54 calls 0x07e178...")
for i in range(0x020c54, 0x020c54 + 0x100, 4):
    if i + 3 >= len(data):
        break
    inst = struct.unpack_from("<I", data, i)[0]
    if (inst >> 26) == 0x25:
        imm26 = inst & 0x3FFFFFF
        if imm26 & 0x2000000:
            imm26 -= 0x4000000
        target = i + imm26 * 4
        print(f"    BL at 0x{i:06x} -> 0x{target:06x}")
