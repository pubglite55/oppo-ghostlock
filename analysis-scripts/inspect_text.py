#!/usr/bin/env python3
"""Inspect the .text section content to understand instruction patterns."""
from elftools.elf.elffile import ELFFile
import struct

VMLINUX = "/Users/xiuxiu391/Desktop/oppo/vmlinux.elf"

with open(VMLINUX, "rb") as f:
    elf = ELFFile(f)
    text = elf.get_section_by_name(".text")
    data = text.data()

print(f".text size: 0x{len(data):x} ({len(data)} bytes)")
print(f"Instructions: {len(data)//4}")

# Scan for PACIASP (0xD503233F)
paciasp_count = 0
paciasp_offsets = []
for i in range(0, len(data) - 7, 4):
    inst = struct.unpack_from("<I", data, i)[0]
    if inst == 0xD503233F:
        paciasp_count += 1
        if len(paciasp_offsets) < 20:
            paciasp_offsets.append(i)

print(f"\nPACIASP instructions found: {paciasp_count}")
print(f"First 20 PACIASP offsets: {[f'0x{o:x}' for o in paciasp_offsets]}")

# Show what follows the first few PACIASP
for off in paciasp_offsets[:5]:
    print(f"\n--- At offset 0x{off:x} ---")
    for j in range(0, 16, 4):
        inst = struct.unpack_from("<I", data, off + j)[0]
        print(f"  +{j:2d}: 0x{inst:08x}")

# Check first bytes
print(f"\nFirst 32 bytes:")
for i in range(0, 32, 4):
    inst = struct.unpack_from("<I", data, i)[0]
    print(f"  0x{i:06x}: 0x{inst:08x}")

# Also look at the symbol table
for section in elf.iter_sections():
    if section.name == ".symtab":
        print(f"\nSymbols in .symtab:")
        for sym in section.iter_symbols():
            print(f"  name={sym.name!r} value=0x{sym.entry.st_value:x} size={sym.entry.st_size} type={sym.entry.st_info}")

# Check for SUB SP patterns near PACIASP
sub_sp_count = 0
for i in range(0, len(data) - 7, 4):
    inst = struct.unpack_from("<I", data, i)[0]
    if (inst & 0xFFC003FF) == 0xD10003FF or (inst & 0xFFC003FF) == 0xF10003FF:
        sub_sp_count += 1

print(f"\nSUB SP,SP,#imm instructions found: {sub_sp_count}")

# Check for STP x29,x30 patterns
stp_count = 0
for i in range(0, len(data) - 7, 4):
    inst = struct.unpack_from("<I", data, i)[0]
    # STP pre-index: check opcode bits
    if ((inst >> 22) & 0x3FF) == 0x2A7 and (inst & 0x1F) == 29 and ((inst >> 10) & 0x1F) == 30:
        stp_count += 1

print(f"STP x29,x30,[sp,#-N]! instructions found: {stp_count}")

# Check for BL instructions
bl_count = 0
for i in range(0, len(data) - 3, 4):
    inst = struct.unpack_from("<I", data, i)[0]
    if (inst >> 26) == 0x25:
        bl_count += 1

print(f"BL instructions found: {bl_count}")

# Look at some typical function prologues
print(f"\nScanning for PACIASP + STP x29,x30 prologues:")
count = 0
for i in range(0, len(data) - 11, 4):
    inst0 = struct.unpack_from("<I", data, i)[0]
    if inst0 == 0xD503233F:
        inst1 = struct.unpack_from("<I", data, i + 4)[0]
        if ((inst1 >> 22) & 0x3FF) == 0x2A7 and (inst1 & 0x1F) == 29 and ((inst1 >> 10) & 0x1F) == 30:
            imm7 = (inst1 >> 15) & 0x7F
            if imm7 & 0x40:
                imm7 -= 0x80
            frame = abs(imm7 * 8)
            if count < 20:
                print(f"  0x{i:x}: PACIASP + STP x29,x30,[sp,#-{frame}] (imm7=0x{(inst1>>15)&0x7F:x})")
            count += 1

print(f"Total PACIASP + STP prologues: {count}")

# Also show PACIASP + SUB SP
print(f"\nScanning for PACIASP + SUB SP prologues:")
count2 = 0
for i in range(0, len(data) - 7, 4):
    inst0 = struct.unpack_from("<I", data, i)[0]
    if inst0 == 0xD503233F:
        inst1 = struct.unpack_from("<I", data, i + 4)[0]
        if (inst1 & 0xFFC003FF) == 0xD10003FF:
            imm12 = (inst1 >> 10) & 0xFFF
            if count2 < 20:
                print(f"  0x{i:x}: PACIASP + SUB SP,SP,#0x{imm12:x} ({imm12} bytes)")
            count2 += 1
        elif (inst1 & 0xFFC003FF) == 0xF10003FF:
            imm12 = (inst1 >> 10) & 0xFFF
            frame = imm12 << 12
            if count2 < 20:
                print(f"  0x{i:x}: PACIASP + SUB SP,SP,#0x{imm12:x}<<12 = 0x{frame:x} ({frame} bytes)")
            count2 += 1

print(f"Total PACIASP + SUB SP prologues: {count2}")
