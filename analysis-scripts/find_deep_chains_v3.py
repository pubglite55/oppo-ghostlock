#!/usr/bin/env python3
"""Analyze vmlinux.elf call chains for GhostLock exploit — v3 (ET_REL aware)."""

import struct
import sys
from elftools.elf.elffile import ELFFile
from collections import defaultdict

VMLINUX = "/Users/xiuxiu391/Desktop/oppo/vmlinux.elf"
MIN_DEPTH = 0x358  # 856 bytes — rt_mutex_waiter offset

def load_text():
    with open(VMLINUX, "rb") as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name(".text")
        data = text.data()
    return data

def find_functions(data):
    """
    Find function prologues: PACIASP (0xD503233F) followed by frame setup.
    Returns dict: offset -> frame_size
    """
    funcs = {}
    i = 0
    while i + 11 < len(data):
        inst0 = struct.unpack_from("<I", data, i)[0]
        if inst0 != 0xD503233F:
            i += 4
            continue

        func_off = i
        inst1 = struct.unpack_from("<I", data, i + 4)[0]
        frame_size = 0

        # Pattern 1: PACIASP + SUB SP,SP,#imm (sh=0)
        if (inst1 & 0xFFC003FF) == 0xD10003FF:
            imm12 = (inst1 >> 10) & 0xFFF
            frame_size = imm12

        # Pattern 2: PACIASP + SUB SP,SP,#imm (sh=1, shift by 12)
        elif (inst1 & 0xFFC003FF) == 0xF10003FF:
            imm12 = (inst1 >> 10) & 0xFFF
            frame_size = imm12 << 12

        # Pattern 3: PACIASP + STP x29,x30,[sp,#-N]! (pre-index writeback)
        elif (((inst1 >> 22) & 0x3FF) == 0x2A7 and
              (inst1 & 0x1F) == 29 and
              ((inst1 >> 10) & 0x1F) == 30 and
              ((inst1 >> 5) & 0x1F) == 31):
            imm7 = (inst1 >> 15) & 0x7F
            if imm7 & 0x40:
                imm7 -= 0x80
            frame_size = abs(imm7 * 8)

        # Pattern 4: PACIASP + MOV x29,sp (ADD x29,sp,#0) + next instruction is frame setup
        elif inst1 == 0x910003FD:
            if i + 11 < len(data):
                inst2 = struct.unpack_from("<I", data, i + 8)[0]
                if (inst2 & 0xFFC003FF) == 0xD10003FF:
                    frame_size = (inst2 >> 10) & 0xFFF
                elif (inst2 & 0xFFC003FF) == 0xF10003FF:
                    frame_size = ((inst2 >> 10) & 0xFFF) << 12
                elif (((inst2 >> 22) & 0x3FF) == 0x2A7 and
                      (inst2 & 0x1F) == 29 and
                      ((inst2 >> 10) & 0x1F) == 30 and
                      ((inst2 >> 5) & 0x1F) == 31):
                    imm7 = (inst2 >> 15) & 0x7F
                    if imm7 & 0x40:
                        imm7 -= 0x80
                    frame_size = abs(imm7 * 8)

        if frame_size > 0:
            funcs[func_off] = frame_size
        i += 4

    return funcs

def build_bl_map(data, func_offsets):
    """Build call graph: for each BL instruction, record caller offset -> callee offset."""
    func_set = set(func_offsets.keys())
    # We need to handle both intra-.text BL and external calls
    # For intra-.text: caller_off + imm26*4 gives callee_off (if it's in our function list)
    bl_calls = defaultdict(list)  # caller_off -> [callee_off]

    for i in range(0, len(data) - 3, 4):
        inst = struct.unpack_from("<I", data, i)[0]
        if (inst >> 26) == 0x25:  # BL
            imm26 = inst & 0x3FFFFFF
            if imm26 & 0x2000000:
                imm26 -= 0x4000000
            callee_off = i + imm26 * 4
            caller_off = i
            bl_calls[caller_off].append(callee_off)

    return bl_calls

def compute_chain_depths(funcs, bl_calls):
    """
    For each function, compute the maximum call chain depth from any root.
    Returns dict: func_off -> max_depth
    """
    # Build reverse map: callee_off -> [caller_off]
    rev_calls = defaultdict(list)
    for caller, callees in bl_calls.items():
        for callee in callees:
            rev_calls[callee].append(caller)

    # For each function, trace backward (through callers) to compute max depth
    cache = {}
    visiting = set()

    def depth(off):
        if off in cache:
            return cache[off]
        if off in visiting:
            return 0  # cycle protection
        visiting.add(off)

        frame = funcs.get(off, 0)
        callers = rev_calls.get(off, [])

        if not callers:
            cache[off] = frame
            visiting.discard(off)
            return frame

        max_caller = 0
        for c in callers:
            if c in funcs:  # only follow to known functions
                d = depth(c)
                if d > max_caller:
                    max_caller = d

        result = frame + max_caller
        cache[off] = result
        visiting.discard(off)
        return result

    depths = {}
    for off in funcs:
        depths[off] = depth(off)

    return depths, rev_calls

def build_chain(funcs, rev_calls, target):
    """Build the actual call chain from root to target."""
    chain = [target]
    visited = {target}
    current = target

    for _ in range(30):  # max depth
        callers = [c for c in rev_calls.get(current, []) if c in funcs and c not in visited]
        if not callers:
            break
        best = max(callers, key=lambda c: funcs[c])
        visited.add(best)
        chain.append(best)
        current = best

    chain.reverse()
    return chain

def main():
    print("=" * 80)
    print("GHOSTLOCK (CVE-2026-43499) — SYSCALL CHAIN DEPTH ANALYSIS")
    print("Target: waiter rt_mutex_waiter at stack_top - 0x358 (856 bytes)")
    print("=" * 80)

    data = load_text()
    print(f"[+] .text section: 0x{len(data):x} bytes ({len(data)} bytes)")

    print(f"\n[+] Scanning for function prologues...")
    funcs = find_functions(data)
    print(f"[+] Found {len(funcs)} functions with stack frames")

    # Frame size distribution
    sizes = sorted(funcs.values(), reverse=True)
    print(f"[+] Frame sizes: min={min(sizes)}, max={max(sizes)}, median={sizes[len(sizes)//2]}")

    # Distribution
    ranges = [(0, 64), (64, 128), (128, 192), (192, 256), (256, 384), (384, 512),
              (512, 768), (768, 1024), (1024, 2048), (2048, 4096), (4096, 8192), (8192, 16384)]
    print(f"[+] Frame size distribution:")
    for lo, hi in ranges:
        count = sum(1 for s in funcs.values() if lo <= s < hi)
        bar = "#" * min(count // 5, 60)
        print(f"    {lo:5d}-{hi:5d}: {count:5d} {bar}")

    # Show largest frames
    large = sorted(funcs.items(), key=lambda x: -x[1])[:30]
    print(f"\n[+] Largest frames:")
    for off, size in large:
        print(f"    0x{off:06x}: frame={size} bytes (0x{size:x})")

    print(f"\n[+] Building call graph...")
    bl_calls = build_bl_map(data, funcs)
    total_bls = sum(len(v) for v in bl_calls.values())
    print(f"[+] Total BL instructions: {total_bls}")
    # How many BL targets hit a known function?
    known_targets = sum(1 for callees in bl_calls.values() for c in callees if c in funcs)
    print(f"[+] BL targets hitting known functions: {known_targets}")

    print(f"\n[+] Computing max chain depths (recursive, may take a moment)...")
    depths, rev_calls = compute_chain_depths(funcs, bl_calls)

    # Qualifying chains
    qualifying = [(off, d) for off, d in depths.items() if d >= MIN_DEPTH]
    qualifying.sort(key=lambda x: -x[1])
    print(f"[+] Chains with total depth >= 0x{MIN_DEPTH:x} ({MIN_DEPTH} bytes): {len(qualifying)}")

    # Display top chains
    print(f"\n{'=' * 80}")
    print(f"TOP CALL CHAINS (>= 0x{MIN_DEPTH:x} bytes = {MIN_DEPTH} bytes)")
    print(f"{'=' * 80}")

    seen = set()
    count = 0
    for off, depth in qualifying:
        if count >= 40:
            break
        chain = build_chain(funcs, rev_calls, off)
        total = sum(funcs[a] for a in chain)
        if total < MIN_DEPTH:
            continue
        key = tuple(chain)
        if key in seen:
            continue
        seen.add(key)
        count += 1

        print(f"\n--- Chain #{count}: total = {total} bytes (0x{total:x}) [{len(chain)} frames] ---")
        for idx, a in enumerate(chain):
            label = "ROOT" if idx == 0 else ("LEAF" if idx == len(chain) - 1 else f"L{idx}")
            print(f"    [{label:>4s}] 0x{a:06x}: frame = {funcs[a]} bytes (0x{funcs[a]:x})")

    # Sweet spot: chains between 856 and 1400 bytes
    print(f"\n{'=' * 80}")
    print(f"SWEET SPOT: chains with depth 856-1400 bytes (ideal for GhostLock)")
    print(f"{'=' * 80}")

    sweet = [(off, d) for off, d in depths.items() if 856 <= d <= 1400]
    sweet.sort(key=lambda x: -x[1])
    print(f"Found {len(sweet)} chains in sweet spot")

    seen2 = set()
    count2 = 0
    for off, depth in sweet:
        if count2 >= 30:
            break
        chain = build_chain(funcs, rev_calls, off)
        total = sum(funcs[a] for a in chain)
        if total < 856 or total > 1400:
            continue
        key = tuple(chain)
        if key in seen2:
            continue
        seen2.add(key)
        count2 += 1

        print(f"\n--- Sweet #{count2}: total = {total} bytes (0x{total:x}) ---")
        for idx, a in enumerate(chain):
            label = "ROOT" if idx == 0 else ("LEAF" if idx == len(chain) - 1 else f"L{idx}")
            print(f"    [{label:>4s}] 0x{a:06x}: frame = {funcs[a]} bytes (0x{funcs[a]:x})")

    # Now specifically check the futex path
    print(f"\n{'=' * 80}")
    print("FUTEX CHAIN ANALYSIS (known: total = 976 bytes)")
    print("Looking for functions that call into futex-related chains...")
    print(f"{'=' * 80}")

    # The futex chain: sys_futex(0x70) -> do_futex(0x1c0) -> futex_wait_requeue_pi(0x1a0) = 0x3d0 (976B)
    # Search for functions with frame sizes matching these known values
    futex_frames = {0x70, 0x1c0, 0x1a0}
    futex_func_offsets = [off for off, s in funcs.items() if s in futex_frames]
    print(f"Functions matching futex frame sizes (0x70, 0x1c0, 0x1a0): {len(futex_func_offsets)}")
    for off in futex_func_offsets[:20]:
        d = depths.get(off, 0)
        print(f"  0x{off:06x}: frame={funcs[off]} bytes, max_chain={d} bytes (0x{d:x})")

    # Check for deep chains by looking at specific patterns
    # Find functions with frame=0x70 (like sys_futex)
    print(f"\n[+] Functions with frame = 0x70 (sys_futex-like):")
    for off, s in funcs.items():
        if s == 0x70:
            d = depths.get(off, 0)
            if d >= MIN_DEPTH:
                chain = build_chain(funcs, rev_calls, off)
                total = sum(funcs[a] for a in chain)
                if total >= MIN_DEPTH:
                    print(f"  0x{off:06x}: chain = {total} bytes")
                    for idx, a in enumerate(chain):
                        print(f"    [{idx}] 0x{a:06x}: frame = {funcs[a]} bytes")

    # Broader: find chains where leaf has small frame (syscall entry) and total >= 856
    print(f"\n[+] All chains with leaf frame <= 0x120 and total >= {MIN_DEPTH}:")
    small_leaf_chains = []
    for off, d in depths.items():
        if d >= MIN_DEPTH and funcs[off] <= 0x120:
            chain = build_chain(funcs, rev_calls, off)
            total = sum(funcs[a] for a in chain)
            if total >= MIN_DEPTH:
                small_leaf_chains.append((off, total, chain))

    small_leaf_chains.sort(key=lambda x: -x[1])
    print(f"Found {len(small_leaf_chains)} chains")

    seen3 = set()
    count3 = 0
    for off, total, chain in small_leaf_chains:
        if count3 >= 25:
            break
        key = tuple(chain)
        if key in seen3:
            continue
        seen3.add(key)
        count3 += 1
        print(f"\n  Chain #{count3}: total = {total} bytes (0x{total:x})")
        for idx, a in enumerate(chain):
            label = "ROOT" if idx == 0 else ("LEAF" if idx == len(chain) - 1 else f"L{idx}")
            print(f"    [{label:>4s}] 0x{a:06x}: frame = {funcs[a]} bytes")

    # Summary statistics
    print(f"\n{'=' * 80}")
    print("SUMMARY")
    print(f"{'=' * 80}")
    print(f"Total functions found: {len(funcs)}")
    print(f"Total BL instructions: {total_bls}")
    print(f"Chains >= 0x{MIN_DEPTH:x} ({MIN_DEPTH} bytes): {len(qualifying)}")
    if qualifying:
        print(f"Deepest chain: {qualifying[0][1]} bytes (0x{qualifying[0][1]:x})")
        print(f"Top 5 depths:")
        for i, (off, d) in enumerate(qualifying[:5]):
            print(f"  #{i+1}: {d} bytes (0x{d:x}) at 0x{off:06x}")

if __name__ == "__main__":
    main()
