#!/usr/bin/env python3
"""Find syscall call chains with total stack depth >= 856 bytes (0x358) in vmlinux.elf — v2."""

import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from collections import defaultdict

VMLINUX = "/Users/xiuxiu391/Desktop/oppo/vmlinux.elf"
MIN_DEPTH = 0x358  # 856 bytes

def load_elf():
    with open(VMLINUX, "rb") as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name(".text")
        if text is None:
            raise RuntimeError("No .text section")
        text_data = text.data()
        text_base = text["sh_addr"]

        # Try to load symbol table
        symbols = {}
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for sym in section.iter_symbols():
                    if sym.name and sym.entry.st_value:
                        symbols[sym.entry.st_value] = sym.name

        # Also check .dynsym
        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym:
            for sym in dynsym.iter_symbols():
                if sym.name and sym.entry.st_value:
                    symbols[sym.entry.st_value] = sym.name

    return text_data, text_base, symbols

def find_functions_and_frames(data, vaddr):
    """
    Find function prologues and their frame sizes.
    Patterns:
    1. PACIASP + SUB SP,SP,#imm (with or without shift)
    2. PACIASP + STP x29,x30,[SP,#-imm]! (pre-index STP)
    """
    funcs = {}  # addr -> (frame_size, prologue_type)

    i = 0
    while i + 7 < len(data):
        inst = struct.unpack_from("<I", data, i)[0]
        if inst == 0xD503233F:  # PACIASP
            func_addr = vaddr + i
            next_inst = struct.unpack_from("<I", data, i + 4)[0]

            # Pattern 1: SUB SP, SP, #imm
            # Encoding: sf=1 op=1 S=0 10001 sh imm12 Rn=SP Rd=SP
            # 0xD10003FF with sh=0, or 0xF10003FF with sh=1
            if (next_inst & 0xFFC003FF) == 0xD10003FF or (next_inst & 0xFFC003FF) == 0xF10003FF:
                sh = (next_inst >> 22) & 1
                imm12 = (next_inst >> 10) & 0xFFF
                frame_size = imm12 << (12 * sh)
                if frame_size > 0:
                    funcs[func_addr] = (frame_size, "sub_sp")
                i += 8
                continue

            # Pattern 2: STP x29, x30, [SP, #imm]! (pre-index, negative imm)
            # Encoding: opc=10 1 0 1 0 0 1 1 1 imm7 Rt2=11110(Rt2=x30) Rn=11111(SP) Rt=11101(Rt=x29)
            # Pre-index: bits 31-22 = 10 1 0 1 0 0 1 1 1 0 = 0xA9BF
            # Actually: 10_101_0_011_1_imm7_11110_11111_11101
            # bit 31-30: opc=10
            # bit 29: 1 (L=1 for load? No, for STP L=0)
            # Let me be more careful.

            # STP pre-index encoding (64-bit):
            # opc=10, 1, 0, 1, 0, 0, 1, 1, 1, imm7, Rt2, Rn, Rt
            # bit 31:30 = opc = 10
            # bit 29 = 0 (for STP, not LDP)
            # bits 28:27 = 10
            # bit 26 = 1 (pair)
            # bits 25:23 = 001 (pre-index)
            # bit 22 = 0 (STP)
            # Wait, the actual encoding is more nuanced. Let me look at the encoding table.

            # For STP <X1>, <X2>, [<Xn|SP>, #<imm>]! (pre-index, writeback):
            # 10 1 0 1 0 0 1 1 1 imm7 Rt2 Rn Rt
            # = opc(2) 0(1) 1(1) 0(1) 1(1) 0(1) 0(1) 1(1) 1(1) imm7(7) Rt2(5) Rn(5) Rt(5)
            # bits: 31-30 opc, 29=0, 28=1, 27=0, 26=1, 25=0, 24=0, 23=1, 22=1

            # Hmm, I'm getting confused. Let me use the actual hex values.

            # STP x29, x30, [sp, #imm]! with pre-index (writeback, negative offset):
            # The instruction has:
            # - bits [31:30] = 10 (opc for 64-bit)
            # - bit [29] = 1 (for STP, 0 would be LDP)
            # Actually, bit 29 is the 'V' bit. For general-purpose register pairs, V=0.

            # Let me just look at common prologues:
            # STP x29, x30, [sp, #-0x10]! = A9BF7BFD
            # STP x29, x30, [sp, #-0x20]! = A9BF03E0... no

            # I'll match by bitmask. STP pre-index for x29,x30 on sp:
            # Pattern: xxA9_xxxx_1111_0111_1011_1101
            # More precisely, the bits we care about:
            # [31:30]=10, [29]=0, [28]=1, [27]=0, [26]=1, [25:23]=011 (pre-index), [22]=1
            # Rn=11111 (sp), Rt=11101 (x29), Rt2=11110 (x30)

            # Encoding: 10 0 1 0 1 0 0 1 1 1 imm7 11110 11111 11101
            # Hmm, bits don't match what I expect.

            # Let me use a simpler approach: just match on known prologue bytes.

            # Actually, the STP pre-index encoding for 64-bit:
            # 10 1 0 1 0 0 1 1 1 imm7 Rt2 Rn Rt
            # where bit 22=1 means pre-index writeback, bit 29=0 for STP

            # Wait, I keep going in circles. Let me just check the bit patterns:
            # opc=10 → bits 31:30 = 10
            # bit 29 = 0 (GPR pair store)
            # bits 28:27 = 10 (for STP/LDP)
            # bit 26 = 1 (pair)
            # bits 25:23 = 011 (pre-index)
            # bit 22 = 1 (writeback)
            # Rn, Rt, Rt2

            # So bits 31:22 = 10_0_10_1_011_1 = 0b1001010111 = 0x257 << 2 = ...

            # Let me just compute: 10 0 101 0 011 1 = 0xA980... no

            # OK let me try a completely different approach. I'll use the known encoding:

            # STP pre-index (64-bit, general purpose):
            # opcode bits: 10 1 0 1 0 0 1 1 1 = 0xA9BF (top 10 bits)
            # So (inst >> 22) & 0x3FF = 0x27E for pre-index
            # And Rt = inst & 0x1F, Rn = (inst >> 5) & 0x1F, Rt2 = (inst >> 10) & 0x1F

            # For STP x29, x30, [sp, #-N]!:
            # Rt = 29 (x29), Rt2 = 30 (x30), Rn = 31 (sp)
            # (inst & 0x1F) = 29 = 0x1D
            # ((inst >> 5) & 0x1F) = 31 = 0x1F
            # ((inst >> 10) & 0x1F) = 30 = 0x1E

            # imm7 = (inst >> 15) & 0x7F
            # The offset = imm7 * 8 (signed, sign-extend from 7 bits)
            # Since it's pre-index with negative offset, imm7 encodes -N/8

            stp_preindex_pattern = (next_inst >> 22) & 0x3FF
            stp_rt = next_inst & 0x1F
            stp_rn = (next_inst >> 5) & 0x1F
            stp_rt2 = (next_inst >> 10) & 0x1F

            # Check if this is STP x29, x30, [sp, #-N]!
            # Pre-index STP for 64-bit: top bits should be 10_1_0100_11_1
            # Let me just compute what (inst >> 22) & 0x3FF should be:
            # bits 31:22 = 10_0_10_1_011_1 = ... let me count:
            # 31=1, 30=0, 29=1, 28=0, 27=1, 26=0, 25=0, 24=1, 23=1, 22=1
            # = 1010100111 = 0x2A7

            # Hmm, actually for STP pre-index:
            # bits 31:30 = opc = 10
            # bit 29 = 0
            # bits 28:27 = 10
            # bit 26 = 1
            # bits 25:23 = 011 (pre-index)
            # bit 22 = 1
            # = 10_0_10_1_011_1

            # Wait, bits 28:27 for STP/LDP are 10, not 01.
            # The ARM manual says:
            # STP: opc 0 1 0 1 0 0 1 0 1 imm7 Rt2 Rn Rt (signed offset)
            # STP pre-index: opc 0 1 0 1 0 0 1 1 1 imm7 Rt2 Rn Rt

            # So bits 31:22 for pre-index 64-bit:
            # 10 0 1 0 1 0 0 1 1 1
            # = 1001010011 = 0x253 ... no that's 10 bits

            # Let me lay it out properly:
            # bit 31: opc[1] = 1
            # bit 30: opc[0] = 0
            # bit 29: 0
            # bit 28: 1
            # bit 27: 0
            # bit 26: 1
            # bit 25: 0
            # bit 24: 0
            # bit 23: 1
            # bit 22: 1

            # So (inst >> 22) & 0x3FF = 1_0_0_1_0_1_0_0_1_1 = 0b1001010011 = 0x253

            # And Rt = x29 = 29, Rt2 = x30 = 30, Rn = sp = 31

            # Let me check with a known instruction:
            # STP x29, x30, [sp, #-0x20]!
            # imm7 = (-0x20 / 8) & 0x7F = (-4) & 0x7F = 0x7C
            # Full: 10_0_101_0_011_1_1111100_11110_11111_11101
            # = 10_0_10_1_0011_1_111_1100_11110_11111_11101

            # Hmm, I realize I need to double-check my bit layout. Let me look at the ARM ARM more carefully.

            # STP <Xt1>, <Xt2>, [<Xn|SP>, #<imm>]! encoding:
            # 31 30 29 28 27 26 25 24 23 22 21..15 14..10 9..5 4..0
            # opc  0  1  0  1  0  0  1  1  1  imm7    Rt2    Rn    Rt

            # For 64-bit: opc=10
            # So bits 31:22 = 10_0_101_0_011_1

            # Let me lay out the bits:
            # 31: 1
            # 30: 0
            # 29: 0
            # 28: 1
            # 27: 0
            # 26: 1
            # 25: 0
            # 24: 0
            # 23: 1
            # 22: 1

            # = 1001010011 binary = 0x253

            # OK so for pre-index STP 64-bit:
            # (inst >> 22) & 0x3FF should be 0x253

            # For x29=29, x30=30, sp=31:
            # Rt=29, Rt2=30, Rn=31

            # Check: Rt should be (inst & 0x1F) = 29
            # Rn should be ((inst >> 5) & 0x1F) = 31
            # Rt2 should be ((inst >> 10) & 0x1F) = 30

            # Hmm, actually I realize the ARM manual uses different bit numbering.
            # Let me just check by looking at known bytes.

            # STP x29, x30, [sp, #-0x20]!:
            # According to online assemblers: 0xA9BF7BFD
            # Let me check:
            # 0xA9BF7BFD = 1010_1001_1011_1111_0111_1011_1111_1101

            # Rt = bits 4:0 = 11101 = 29 ✓
            # Rn = bits 9:5 = 11111 = 31 ✓
            # Rt2 = bits 14:10 = 11110 = 30 ✓
            # imm7 = bits 21:15 = 1111100 = 0x7C = 124
            #   offset = sign_extend(0x7C, 7) * 8 = -4 * 8 = -32 ✓
            # bits 31:22 = 1010_1001_10 = 0x2A7... wait

            # 1010_1001_10 = 0x2A7? Let me count:
            # 1 0 1 0 _ 1 0 0 1 _ 1 0 = 10 bits
            # 1010100110 = 0x2A6

            # Hmm, that doesn't match my expected 0x253. Let me re-examine the encoding.

            # From the ARM ARM (A-profile):
            # STP (Pre-index): opc 0 1 0 1 0 0 1 1 1 imm7 Rt2 Rn Rt

            # So the bits are:
            # 31:30 = opc = 10
            # 29 = 0
            # 28 = 1
            # 27 = 0
            # 26 = 1
            # 25 = 0
            # 24 = 0
            # 23 = 1
            # 22 = 1

            # Binary: 10_0_1_0_1_0_0_1_1_1 = 10 bits
            # = 1001010011 = let me compute:
            # 1*512 + 0*256 + 0*128 + 1*64 + 0*32 + 1*16 + 0*8 + 0*4 + 1*2 + 1*1
            # = 512 + 64 + 16 + 2 + 1 = 595 = 0x253

            # But the actual encoding from 0xA9BF7BFD gives bits 31:22 = 0xA9BF >> 6 = ...

            # Let me recompute from 0xA9BF7BFD:
            # Bits 31:22 of the full instruction = (0xA9BF7BFD >> 10) & 0x3FF
            # = (0x2A6FDFBF) ... no, let me just do the math properly.

            # inst = 0xA9BF7BFD
            # bits 31:22 = (inst >> 10) & 0x3FF
            # = (0xA9BF7BFD >> 10) & 0x3FF
            # = 0x2A6FDF & 0x3FF
            # = 0x1BF ... hmm

            # OK I think I'm overcomplicating this. Let me just use a direct bitmask approach.

            # From the actual instruction 0xA9BF7BFD:
            # binary: 1010_1001_1011_1111_0111_1011_1111_1101

            # bit 31 = 1
            # bit 30 = 0
            # bit 29 = 1
            # bit 28 = 0
            # bit 27 = 1
            # bit 26 = 0
            # bit 25 = 0
            # bit 24 = 1
            # bit 23 = 1
            # bit 22 = 1

            # So bits 31:22 = 10101001101... no wait, that's 11 bits.

            # bits 31:22 (10 bits):
            # bit 31=1, bit 30=0, bit 29=1, bit 28=0, bit 27=1, bit 26=0, bit 25=0, bit 24=1, bit 23=1, bit 22=1
            # = 1010100111 ... that's 10 bits? No, 31-22 = 10 bits.

            # = 1 0 1 0 1 0 0 1 1 1 = 0x2A7

            # Hmm wait, 0xA9BF:
            # 1010 1001 1011 1111
            # bits 31:16 = 0xA9BF
            # bits 31:22 = (0xA9BF >> 6) = 0x2A7 & 0x3FF = 0x2A7

            # So (inst >> 22) & 0x3FF = 0x2A7 for this STP pre-index instruction.

            # But I computed 0x253 from the ARM manual. Let me check:
            # opc 0 1 0 1 0 0 1 1 1
            # = 10 0 1 0 1 0 0 1 1 1
            # = 1010_1001_11 = 0x2A7

            # Wait, I had it wrong before. Let me recount:
            # opc = 10 → bits 31:30 = 10
            # bit 29 = 0
            # bit 28 = 1
            # bit 27 = 0
            # bit 26 = 1
            # bit 25 = 0
            # bit 24 = 0
            # bit 23 = 1
            # bit 22 = 1

            # 10_0_1_0_1_0_0_1_1 = that's only 9 bits for bits 31:23
            # bit 22 = 1

            # So bits 31:22 = 10_0_1010011_1 = 1010_1001_11 = 0x2A7

            # OK so my earlier calculation was wrong. The correct value is 0x2A7.

            # Now let me verify: for STP pre-index, the pattern mask should be:
            # We want to match STP x29, x30, [sp, #-N]!
            # Rt=29, Rt2=30, Rn=31
            # Mask out imm7 (bits 21:15)

            # inst & mask should equal pattern
            # mask bits: all except 21:15
            # mask = 0xFFC00000 | 0x00007FE0 | 0x1F = 0xFFC07FFF? No.

            # Actually, let me use a different approach. I'll match:
            # Top 10 bits (31:22) = 0x2A7
            # Rt (4:0) = 29
            # Rt2 (14:10) = 30
            # Rn (9:5) = 31

            # mask to check: bits 31:22, 14:10, 9:5, 4:0
            # = 0xFFC00000 | 0x00007C00 | 0x000003E0 | 0x0000001F
            # = 0xFFC07FFF

            # pattern: 0x2A7 << 22 | 30 << 10 | 31 << 5 | 29
            # = 0xA9C00000 | 0x00007800 | 0x000003E0 | 0x0000001D
            # = 0xA9C07BFD

            # Hmm, let me compute differently:
            # 0x2A7 << 22 = 0xA9C00000
            # 30 << 10 = 0x7800
            # 31 << 5 = 0x3E0
            # 29 = 0x1D
            # Total = 0xA9C07BFD

            # But the actual instruction is 0xA9BF7BFD, not 0xA9C07BFD.
            # The difference is in bits 21:15 (imm7 = 0x7C vs 0x7E = offset difference).

            # Wait: 0xA9BF vs 0xA9C0... 
            # 0xA9BF = 1010_1001_1011_1111
            # 0xA9C0 = 1010_1001_1100_0000
            # The difference is bits 15:10.

            # Hmm, I think my pattern matching is getting confused. Let me take a step back.

            # For STP x29, x30, [sp, #-0x20]!:
            # imm7 = (-0x20/8) & 0x7F = (-4) & 0x7F = 0x7C

            # Full encoding:
            # bits 31:22 = 0x2A7 (STP pre-index 64-bit)
            # bits 21:15 = 0x7C (imm7)
            # bits 14:10 = 30 (Rt2 = x30)
            # bits 9:5 = 31 (Rn = sp)
            # bits 4:0 = 29 (Rt = x29)

            # Let me compute: 0x2A7 << 22 = ?
            # 0x2A7 = 679
            # 679 << 22 = 679 * 4194304 = 2847932416 = 0xAAF80000

            # That can't be right. Let me recalculate.
            # 0x2A7 = 0b10_1010_0111
            # << 22 = 0b10_1010_0111_000000_000000_00000000
            # = 0xAAE00000? 

            # Actually: 0x2A7 = 0b10_1010_0111
            # In hex: 0x2A7
            # Shifted left by 22: 0x2A7 * 0x400000 = 0x2A7 << 22
            # 0x2A7 = 679
            # 679 * 4194304 = 2,848,034,816... that's too large for 32 bits? No, max is 4,294,967,295.

            # 679 * 4194304 = 2,848,034,816 = 0xAA800000? Let me compute:
            # 679 * 4 = 2716
            # 2716 * 1048576 = ?
            # This is getting tedious. Let me just use Python.

            # Anyway, the point is: I need to match STP x29, x30, [sp, #-N]! patterns.
            # The simplest approach is to check:
            # 1. (inst >> 22) & 0x3FF == 0x2A7 (STP pre-index 64-bit)
            # 2. Rt = inst & 0x1F == 29
            # 3. Rt2 = (inst >> 10) & 0x1F == 30
            # 4. Rn = (inst >> 5) & 0x1F == 31

            # Actually, I realize the mask approach is simpler:
            # We want to match: (inst & MASK) == PATTERN
            # where MASK covers everything except imm7
            # and PATTERN has the right opcode, Rt, Rt2, Rn

            # Let me just use a practical approach in the code.

            pass  # Will handle below

            i += 4
            continue

        i += 4

    return funcs

# OK, the above is getting way too complicated in comments. Let me just write a clean script.


def find_functions_v2(data, vaddr):
    """Find functions and frame sizes using multiple prologue patterns."""
    funcs = {}
    i = 0
    while i + 11 < len(data):  # Need at least 3 instructions
        inst0 = struct.unpack_from("<I", data, i)[0]

        if inst0 == 0xD503233F:  # PACIASP
            func_addr = vaddr + i
            inst1 = struct.unpack_from("<I", data, i + 4)[0]
            frame_size = 0
            prologue_type = None

            # Pattern 1: SUB SP, SP, #imm
            if (inst1 & 0xFFC003FF) == 0xD10003FF:  # SUB SP,SP,#imm (sh=0)
                imm12 = (inst1 >> 10) & 0xFFF
                frame_size = imm12
                prologue_type = "sub_sp"
            elif (inst1 & 0xFFC003FF) == 0xF10003FF:  # SUB SP,SP,#imm (sh=1)
                imm12 = (inst1 >> 10) & 0xFFF
                frame_size = imm12 << 12
                prologue_type = "sub_sp_shifted"

            # Pattern 2: STP x29, x30, [sp, #-N]! (pre-index writeback)
            # This is the most common kernel prologue
            # Check: Rt=x29(29), Rn=sp(31), Rt2=x30(30), opcode bits for STP pre-index
            elif ((inst1 & 0x7FC003FF) == 0x29807BFD and  # STP pre-index 64-bit, x29,x30,[sp,#-N]!
                  ((inst1 >> 10) & 0x1F) == 30 and  # Rt2 = x30
                  ((inst1 >> 5) & 0x1F) == 31 and   # Rn = sp
                  (inst1 & 0x1F) == 29):             # Rt = x29
                imm7 = (inst1 >> 15) & 0x7F
                # Sign extend 7-bit
                if imm7 & 0x40:
                    imm7 -= 0x80
                frame_size = abs(imm7 * 8)
                prologue_type = "stp_preindex"

            # Pattern 3: STP x29, x30, [sp, #-N]! — broader match
            # The opcode for STP pre-index 64-bit is: bits 31:22 = 10_0_101_0_011_1
            # = 0xA980 in top 15 bits... let me use a different mask.

            # Actually, let me just check the top 10 bits and the register fields.
            # STP pre-index (64-bit): (inst >> 22) & 0x3FF == 0x2A7
            # with Rt=29, Rt2=30, Rn=31
            elif (((inst1 >> 22) & 0x3FF) == 0x2A7 and
                  (inst1 & 0x1F) == 29 and
                  ((inst1 >> 5) & 0x1F) == 31 and
                  ((inst1 >> 10) & 0x1F) == 30):
                imm7 = (inst1 >> 15) & 0x7F
                if imm7 & 0x40:
                    imm7 -= 0x80
                frame_size = abs(imm7 * 8)
                prologue_type = "stp_preindex"

            # Pattern 4: MOV x29, sp + SUB SP, SP, #imm (split prologue)
            # inst1 = MOV x29, sp = ADD x29, sp, #0 = 0x910003FD
            # inst2 = SUB SP, SP, #imm
            elif inst1 == 0x910003FD and i + 11 < len(data):
                inst2 = struct.unpack_from("<I", data, i + 8)[0]
                if (inst2 & 0xFFC003FF) == 0xD10003FF:
                    imm12 = (inst2 >> 10) & 0xFFF
                    frame_size = imm12
                    prologue_type = "mov_fp_sub_sp"
                elif (inst2 & 0xFFC003FF) == 0xF10003FF:
                    imm12 = (inst2 >> 10) & 0xFFF
                    frame_size = imm12 << 12
                    prologue_type = "mov_fp_sub_sp_shifted"

            # Pattern 5: STP x29, x30, [sp, #-N]! where N is not aligned to 8
            # (less common, skip for now)

            if frame_size > 0 and prologue_type:
                funcs[func_addr] = (frame_size, prologue_type)

            i += 4
            continue

        i += 4

    return funcs


def build_call_graph(data, vaddr, known_funcs):
    """Build BL call graph. Returns: caller -> [callee] and callee -> [caller]."""
    func_addrs = set(known_funcs.keys())
    bl_calls = defaultdict(list)  # caller -> [callee]
    rev_calls = defaultdict(list)  # callee -> [caller]

    for i in range(0, len(data) - 3, 4):
        inst = struct.unpack_from("<I", data, i)[0]
        if (inst >> 26) == 0x25:  # BL
            imm26 = inst & 0x3FFFFFF
            if imm26 & 0x2000000:
                imm26 = imm26 - 0x4000000
            caller = vaddr + i
            callee = vaddr + i + imm26 * 4
            bl_calls[caller].append(callee)

    return bl_calls


def trace_max_depth(funcs, bl_calls):
    """For each function, compute the max call chain depth (sum of all frame sizes)."""
    # Build reverse map: callee -> [callers that call it via BL]
    rev_calls = defaultdict(list)
    for caller, callees in bl_calls.items():
        for callee in callees:
            if callee in funcs:
                rev_calls[callee].append(caller)

    cache = {}
    def max_depth(addr, visited):
        if addr in cache:
            return cache[addr]
        frame = funcs.get(addr, (0, ""))[0]
        callers = [c for c in rev_calls.get(addr, []) if c in funcs and c not in visited]
        if not callers:
            cache[addr] = frame
            return frame
        best = max(max_depth(c, visited | {addr}) for c in callers)
        result = frame + best
        cache[addr] = result
        return result

    depths = {}
    for addr in funcs:
        depths[addr] = max_depth(addr, set())

    return depths, rev_calls


def build_chain(funcs, rev_calls, target, max_len=20):
    """Build the actual call chain from root to target."""
    chain = [(target, funcs[target][0], funcs[target][1])]
    visited = {target}
    current = target

    for _ in range(max_len):
        callers = [c for c in rev_calls.get(current, []) if c in funcs and c not in visited]
        if not callers:
            break
        # Pick caller with largest frame
        best = max(callers, key=lambda c: funcs[c][0])
        visited.add(best)
        chain.append((best, funcs[best][0], funcs[best][1]))
        current = best

    chain.reverse()
    return chain


def main():
    print("=" * 80)
    print("VMLINUX.ELF — SYSCALL CALL CHAIN DEPTH ANALYSIS")
    print("=" * 80)

    text_data, text_base, symbols = load_elf()
    print(f"[+] .text: vaddr=0x{text_base:x}, size=0x{len(text_data):x}")
    print(f"[+] Symbols loaded: {len(symbols)}")

    # Show some known symbols
    known_syms = {a: n for a, n in symbols.items() if n.startswith("sys_") or n.startswith("__arm64_sys_")}
    print(f"[+] sys_* symbols: {len(known_syms)}")
    for a in sorted(known_syms.keys())[:20]:
        print(f"    0x{a:x}: {known_syms[a]}")

    print(f"\n[+] Scanning for function prologues...")
    funcs = find_functions_v2(text_data, text_base)
    print(f"[+] Found {len(funcs)} functions with stack frames")

    # Frame size distribution
    frame_sizes = [s for s, _ in funcs.values()]
    print(f"[+] Frame size range: {min(frame_sizes)} - {max(frame_sizes)} bytes")
    print(f"[+] Frame size distribution:")
    buckets = [0] * 12  # 0-64, 64-128, 128-256, 256-512, 512-1K, 1K-2K, 2K-4K, 4K-8K, 8K-16K, 16K-32K, 32K-64K, 64K+
    labels = ["0-64", "64-128", "128-256", "256-512", "512-1K", "1K-2K", "2K-4K", "4K-8K", "8K-16K", "16K-32K", "32K-64K", "64K+"]
    for s in frame_sizes:
        if s < 64: buckets[0] += 1
        elif s < 128: buckets[1] += 1
        elif s < 256: buckets[2] += 1
        elif s < 512: buckets[3] += 1
        elif s < 1024: buckets[4] += 1
        elif s < 2048: buckets[5] += 1
        elif s < 4096: buckets[6] += 1
        elif s < 8192: buckets[7] += 1
        elif s < 16384: buckets[8] += 1
        elif s < 32768: buckets[9] += 1
        elif s < 65536: buckets[10] += 1
        else: buckets[11] += 1
    for label, count in zip(labels, buckets):
        bar = "#" * min(count // 10, 50)
        print(f"    {label:>8s}: {count:5d} {bar}")

    print(f"\n[+] Building call graph...")
    bl_calls = build_call_graph(text_data, text_base, funcs)
    print(f"[+] BL instructions: {sum(len(v) for v in bl_calls.values())}")

    print(f"\n[+] Computing max chain depths (this may take a while)...")
    depths, rev_calls = trace_max_depth(funcs, bl_calls)

    # Filter to chains >= MIN_DEPTH
    qualifying = [(a, d) for a, d in depths.items() if d >= MIN_DEPTH]
    qualifying.sort(key=lambda x: -x[1])

    print(f"[+] Chains with depth >= 0x{MIN_DEPTH:x} ({MIN_DEPTH} bytes): {len(qualifying)}")

    # Build and display top chains
    print(f"\n{'=' * 80}")
    print(f"TOP 50 DEEPEST CALL CHAINS (>= 0x{MIN_DEPTH:x} / {MIN_DEPTH} bytes)")
    print(f"{'=' * 80}")

    seen_chains = set()
    count = 0
    for addr, depth in qualifying:
        if count >= 50:
            break
        chain = build_chain(funcs, rev_calls, addr)
        total = sum(f for _, f, _ in chain)
        if total < MIN_DEPTH:
            continue
        key = tuple(a for a, _, _ in chain)
        if key in seen_chains:
            continue
        seen_chains.add(key)
        count += 1

        # Try to resolve names
        names = []
        for a, f, t in chain:
            name = symbols.get(a, f"sub_{a:x}")
            names.append(name)

        print(f"\n--- Chain #{count}: total = 0x{total:x} ({total} bytes), {len(chain)} frames ---")
        for idx, (a, f, t) in enumerate(chain):
            name = symbols.get(a, f"sub_{a:x}")
            marker = " <-- LEAF" if idx == len(chain) - 1 else (" <-- ROOT" if idx == 0 else "")
            print(f"    [{idx}] 0x{a:x}: frame=0x{f:x} ({f}B) [{t}] {name}{marker}")

    # Specifically look for syscall-sized frames
    print(f"\n{'=' * 80}")
    print("SYSCALL-RELEVANT CHAINS (target frame sizes typical of syscalls)")
    print(f"{'=' * 80}")

    # sys_futex total = 976B. We need >= 856B total.
    # Look for chains where the LEAF has a small-ish frame (syscall wrapper)
    # and the chain accumulates to >= 856B
    syscall_chains = []
    for addr, depth in depths.items():
        if depth < MIN_DEPTH:
            continue
        frame = funcs[addr][0]
        # A syscall wrapper typically has a small frame (0x40-0x100)
        if 0x30 <= frame <= 0x120:
            chain = build_chain(funcs, rev_calls, addr)
            total = sum(f for _, f, _ in chain)
            if total >= MIN_DEPTH:
                syscall_chains.append((addr, frame, depth, chain))

    syscall_chains.sort(key=lambda x: -x[2])

    print(f"Found {len(syscall_chains)} chains starting from syscall-sized frames")
    for i, (addr, frame, depth, chain) in enumerate(syscall_chains[:20]):
        names = [symbols.get(a, f"sub_{a:x}") for a, _, _ in chain]
        print(f"\n--- SC #{i+1}: leaf 0x{addr:x} (frame=0x{frame:x}), total=0x{depth:x} ({depth}B) ---")
        for idx, ((a, f, t), name) in enumerate(zip(chain, names)):
            print(f"    [{idx}] 0x{a:x}: 0x{f:x}B [{t}] {name}")

    # Also check: what chains have total in range [856, 1200] — the sweet spot
    print(f"\n{'=' * 80}")
    print("SWEET SPOT CHAINS (856B - 1200B total depth)")
    print(f"{'=' * 80}")

    sweet = [(a, d) for a, d in depths.items() if 856 <= d <= 1200]
    sweet.sort(key=lambda x: -x[1])
    print(f"Found {len(sweet)} chains in sweet spot range")

    seen2 = set()
    count2 = 0
    for addr, depth in sweet:
        if count2 >= 20:
            break
        chain = build_chain(funcs, rev_calls, addr)
        total = sum(f for _, f, _ in chain)
        if total < 856 or total > 1200:
            continue
        key = tuple(a for a, _, _ in chain)
        if key in seen2:
            continue
        seen2.add(key)
        count2 += 1

        print(f"\n--- Sweet #{count2}: total = 0x{total:x} ({total}B) ---")
        for idx, (a, f, t) in enumerate(chain):
            name = symbols.get(a, f"sub_{a:x}")
            print(f"    [{idx}] 0x{a:x}: 0x{f:x}B [{t}] {name}")

    # Final: check specific known syscalls
    print(f"\n{'=' * 80}")
    print("CHECKING SPECIFIC KNOWN SYSCALLS")
    print(f"{'=' * 80}")

    check_names = [
        "sys_futex", "__arm64_sys_futex", "do_futex", "futex_wait_requeue_pi",
        "sys_pselect6", "__arm64_sys_pselect6", "core_sys_select",
        "sys_epoll_wait", "__arm64_sys_epoll_wait", "do_epoll_wait",
        "sys_epoll_pwait", "__arm64_sys_epoll_pwait",
        "sys_recvfrom", "__arm64_sys_recvfrom", "___sys_recvfrom",
        "sys_recvmmsg", "__arm64_sys_recvmmsg",
        "sys_sendmmsg", "__arm64_sys_sendmmsg",
        "sys_socket", "__arm64_sys_socket", "__sys_socket",
        "sys_setsockopt", "__arm64_sys_setsockopt", "__sys_setsockopt",
        "sys_getsockopt", "__arm64_sys_getsockopt",
        "sys_ioctl", "__arm64_sys_ioctl", "do_vfs_ioctl",
        "sys_poll", "__arm64_sys_poll", "do_poll",
        "sys_ppoll", "__arm64_sys_ppoll",
        "sys_wait4", "__arm64_sys_wait4", "kernel_wait4",
        "sys_waitid", "__arm64_sys_waitid",
        "sys_mmap", "__arm64_sys_mmap", "ksys_mmap_pgoff",
        "sys_io_uring_setup", "__arm64_sys_io_uring_setup",
        "sys_io_uring_enter", "__arm64_sys_io_uring_enter",
        "sys_bpf", "__arm64_sys_bpf",
        "sys_perf_event_open", "__arm64_sys_perf_event_open",
        "sys_keyctl", "__arm64_sys_keyctl",
        "sys_mq_timedsend", "__arm64_sys_mq_timedsend",
        "sys_mq_timedreceive", "__arm64_sys_mq_timedreceive",
        "sys_semtimedop", "__arm64_sys_semtimedop",
        "sys_clock_nanosleep", "__arm64_sys_clock_nanosleep",
        "sys_nanosleep", "__arm64_sys_nanosleep",
        "sys_select", "__arm64_sys_select",
        "sys_pipe2", "__arm64_sys_pipe2",
        "sys_dup3", "__arm64_sys_dup3",
        "sys_inotify_add_watch", "__arm64_sys_inotify_add_watch",
        "sys_fanotify_mark", "__arm64_sys_fanotify_mark",
        "sys_name_to_handle_at", "__arm64_sys_name_to_handle_at",
        "sys_open_by_handle_at", "__arm64_sys_open_by_handle_at",
        "sys_mount", "__arm64_sys_mount",
        "sys_umount2", "__arm64_sys_umount2",
        "sys_pivot_root", "__arm64_sys_pivot_root",
        "sys_move_mount", "__arm64_sys_move_mount",
        "sys_finit_module", "__arm64_sys_finit_module",
        "sys_delete_module", "__arm64_sys_delete_module",
        "sys_kexec_load", "__arm64_sys_kexec_load",
        "sys_init_module", "__arm64_sys_init_module",
        "sys_faccessat", "__arm64_sys_faccessat",
        "sys_execve", "__arm64_sys_execve",
        "sys_personality", "__arm64_sys_personality",
        "sys_ptrace", "__arm64_sys_ptrace",
    ]

    for name in check_names:
        for addr, sym_name in symbols.items():
            if sym_name == name:
                if addr in funcs:
                    frame = funcs[addr][0]
                    depth = depths.get(addr, 0)
                    chain = build_chain(funcs, rev_calls, addr)
                    total = sum(f for _, f, _ in chain)
                    marker = " *** MEETS DEPTH ***" if total >= MIN_DEPTH else ""
                    print(f"  {name:30s} @ 0x{addr:x}: frame=0x{frame:x} ({frame}B), chain=0x{total:x} ({total}B){marker}")
                    if total >= MIN_DEPTH:
                        for idx, (a, f, t) in enumerate(chain):
                            n = symbols.get(a, f"sub_{a:x}")
                            print(f"      [{idx}] 0x{a:x}: 0x{f:x}B {n}")
                else:
                    print(f"  {name:30s} @ 0x{addr:x}: NO FRAME FOUND")
                break


if __name__ == "__main__":
    main()
