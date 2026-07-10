#!/usr/bin/env python3
"""GhostLock chain analysis v4 — handles intermediate functions without PACIASP."""

import struct
from elftools.elf.elffile import ELFFile
from collections import defaultdict

VMLINUX = "/Users/xiuxiu391/Desktop/oppo/vmlinux.elf"
MIN_DEPTH = 0x358  # 856 bytes

def load_text():
    with open(VMLINUX, "rb") as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name(".text")
        return text.data()

def find_functions(data):
    """Find PACIASP prologues with frame sizes. Returns: offset -> frame_size"""
    funcs = {}
    i = 0
    while i + 11 < len(data):
        inst0 = struct.unpack_from("<I", data, i)[0]
        if inst0 != 0xD503233F:
            i += 4
            continue

        inst1 = struct.unpack_from("<I", data, i + 4)[0]
        frame_size = 0

        # SUB SP,SP,#imm (sh=0)
        if (inst1 & 0xFFC003FF) == 0xD10003FF:
            frame_size = (inst1 >> 10) & 0xFFF
        # SUB SP,SP,#imm (sh=1)
        elif (inst1 & 0xFFC003FF) == 0xF10003FF:
            frame_size = ((inst1 >> 10) & 0xFFF) << 12
        # STP x29,x30,[sp,#-N]! pre-index
        elif (((inst1 >> 22) & 0x3FF) == 0x2A7 and
              (inst1 & 0x1F) == 29 and
              ((inst1 >> 10) & 0x1F) == 30 and
              ((inst1 >> 5) & 0x1F) == 31):
            imm7 = (inst1 >> 15) & 0x7F
            if imm7 & 0x40:
                imm7 -= 0x80
            frame_size = abs(imm7 * 8)
        # MOV x29,sp + SUB SP,SP,#imm
        elif inst1 == 0x910003FD and i + 11 < len(data):
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
            funcs[i] = frame_size
        i += 4

    return funcs

def build_full_call_graph(data):
    """
    Build complete call graph including ALL BL targets (even without prologues).
    Returns: 
      frame_sizes: offset -> frame_size (only PACIASP functions)
      bl_calls: caller -> [callee] (ALL BL targets)
      all_nodes: set of all offsets that appear as BL targets or sources
    """
    frame_sizes = find_functions(data)
    func_set = set(frame_sizes.keys())

    bl_calls = defaultdict(list)
    all_nodes = set()

    for i in range(0, len(data) - 3, 4):
        inst = struct.unpack_from("<I", data, i)[0]
        if (inst >> 26) == 0x25:  # BL
            imm26 = inst & 0x3FFFFFF
            if imm26 & 0x2000000:
                imm26 -= 0x4000000
            target = i + imm26 * 4
            if 0 <= target < len(data):
                bl_calls[i].append(target)
                all_nodes.add(i)
                all_nodes.add(target)

    return frame_sizes, bl_calls, all_nodes

def compute_depths(frame_sizes, bl_calls, all_nodes):
    """
    Compute max chain depth for every node in the call graph.
    Uses ALL nodes (not just PACIASP functions) for connectivity.
    """
    # Reverse map: callee -> [callers]
    rev_calls = defaultdict(list)
    for caller, callees in bl_calls.items():
        for callee in callees:
            rev_calls[callee].append(caller)

    def get_frame(off):
        return frame_sizes.get(off, 0)

    cache = {}
    visiting = set()

    def depth(off):
        if off in cache:
            return cache[off]
        if off in visiting:
            return 0
        visiting.add(off)

        frame = get_frame(off)
        callers = rev_calls.get(off, [])

        if not callers:
            cache[off] = frame
            visiting.discard(off)
            return frame

        # Follow ALL callers (not just those in frame_sizes)
        max_caller = max((depth(c) for c in callers), default=0)
        result = frame + max_caller
        cache[off] = result
        visiting.discard(off)
        return result

    # Compute depth for all nodes that have frames
    depths = {}
    for off in all_nodes:
        depths[off] = depth(off)

    return depths, rev_calls

def build_chain(rev_calls, frame_sizes, target, max_len=30):
    """Build actual call chain from root to target."""
    def get_frame(off):
        return frame_sizes.get(off, 0)

    chain = [target]
    visited = {target}
    current = target

    for _ in range(max_len):
        callers = [c for c in rev_calls.get(current, []) if c not in visited]
        if not callers:
            break
        # Pick caller with largest depth (heuristic for most interesting chain)
        best = max(callers, key=lambda c: get_frame(c))
        visited.add(best)
        chain.append(best)
        current = best

    chain.reverse()
    return chain

def main():
    print("=" * 80)
    print("GHOSTLOCK (CVE-2026-43499) — SYSCALL CHAIN ANALYSIS v4")
    print("Target: waiter rt_mutex_waiter at stack_top - 0x358 (856 bytes)")
    print("=" * 80)

    data = load_text()
    print(f"[+] .text: 0x{len(data):x} bytes")

    frame_sizes, bl_calls, all_nodes = build_full_call_graph(data)
    print(f"[+] Functions with PACIASP prologue: {len(frame_sizes)}")
    print(f"[+] Total call graph nodes: {len(all_nodes)}")
    print(f"[+] Total BL edges: {sum(len(v) for v in bl_calls.values())}")

    # Frame size stats
    sizes = sorted(frame_sizes.values(), reverse=True)
    print(f"[+] Max frame: {sizes[0]} bytes (0x{sizes[0]:x})")
    print(f"[+] Median frame: {sizes[len(sizes)//2]} bytes")

    print(f"\n[+] Computing chain depths across ALL call graph nodes...")
    depths, rev_calls = compute_depths(frame_sizes, bl_calls, all_nodes)

    # Filter qualifying
    qualifying = [(off, d) for off, d in depths.items() if d >= MIN_DEPTH and frame_sizes.get(off, 0) > 0]
    qualifying.sort(key=lambda x: -x[1])
    print(f"[+] Chains >= 0x{MIN_DEPTH:x} ({MIN_DEPTH} bytes) ending at PACIASP functions: {len(qualifying)}")

    # Top chains
    print(f"\n{'=' * 80}")
    print(f"TOP CALL CHAINS (>= {MIN_DEPTH} bytes)")
    print(f"{'=' * 80}")

    seen = set()
    count = 0
    for off, depth in qualifying:
        if count >= 40:
            break
        chain = build_chain(rev_calls, frame_sizes, off)
        total = sum(frame_sizes.get(a, 0) for a in chain)
        if total < MIN_DEPTH:
            continue
        key = tuple(chain)
        if key in seen:
            continue
        seen.add(key)
        count += 1

        print(f"\n--- Chain #{count}: total = {total} bytes (0x{total:x}) [{len(chain)} nodes] ---")
        for idx, a in enumerate(chain):
            fs = frame_sizes.get(a, 0)
            marker = " <-- LEAF" if idx == len(chain) - 1 else (" <-- ROOT" if idx == 0 else "")
            has_frame = "[F]" if fs > 0 else "[---]"
            print(f"    [{idx:2d}] 0x{a:06x}: frame = {fs:4d}B {has_frame}{marker}")

    # Sweet spot
    print(f"\n{'=' * 80}")
    print(f"SWEET SPOT: 856-1400 bytes")
    print(f"{'=' * 80}")

    sweet = [(off, d) for off, d in depths.items() if 856 <= d <= 1400 and frame_sizes.get(off, 0) > 0]
    sweet.sort(key=lambda x: -x[1])
    print(f"Found {len(sweet)} chains in sweet spot")

    seen2 = set()
    count2 = 0
    for off, depth in sweet:
        if count2 >= 25:
            break
        chain = build_chain(rev_calls, frame_sizes, off)
        total = sum(frame_sizes.get(a, 0) for a in chain)
        if total < 856 or total > 1400:
            continue
        key = tuple(chain)
        if key in seen2:
            continue
        seen2.add(key)
        count2 += 1

        print(f"\n--- Sweet #{count2}: total = {total} bytes (0x{total:x}) ---")
        for idx, a in enumerate(chain):
            fs = frame_sizes.get(a, 0)
            has_frame = "[F]" if fs > 0 else "[---]"
            print(f"    [{idx:2d}] 0x{a:06x}: frame = {fs:4d}B {has_frame}")

    # Specifically check the futex-like chain
    print(f"\n{'=' * 80}")
    print("FUTEX CHAIN VERIFICATION")
    print("Known: sys_futex(0x70) + do_futex(0x1c0) + futex_wait_requeue_pi(0x1a0) = 976B")
    print(f"{'=' * 80}")

    # Find functions with frame = 0x70, 0x1c0, 0x1a0
    for target_frame, name in [(0x70, "sys_futex-like"), (0x1c0, "do_futex-like"), (0x1a0, "futex_wait_requeue_pi-like")]:
        matches = [(off, depths.get(off, 0)) for off, s in frame_sizes.items() if s == target_frame]
        matches.sort(key=lambda x: -x[1])
        print(f"\n  Functions with frame=0x{target_frame:x} ({name}), sorted by chain depth:")
        for off, d in matches[:5]:
            chain = build_chain(rev_calls, frame_sizes, off)
            total = sum(frame_sizes.get(a, 0) for a in chain)
            print(f"    0x{off:06x}: own={target_frame}B, chain_depth={d}B, chain_total={total}B")
            for idx, a in enumerate(chain):
                fs = frame_sizes.get(a, 0)
                print(f"      [{idx}] 0x{a:06x}: {fs}B")

    # Large chain analysis: what leaf functions have deepest chains?
    print(f"\n{'=' * 80}")
    print("DEEP CHAINS ANALYSIS")
    print(f"{'=' * 80}")

    all_deep = [(off, d) for off, d in depths.items() if d >= MIN_DEPTH]
    all_deep.sort(key=lambda x: -x[1])
    print(f"Total nodes with chain depth >= {MIN_DEPTH}: {len(all_deep)}")

    # Show deepest 30
    print(f"\nDeepest 30 chains:")
    for i, (off, d) in enumerate(all_deep[:30]):
        fs = frame_sizes.get(off, 0)
        chain = build_chain(rev_calls, frame_sizes, off)
        total = sum(frame_sizes.get(a, 0) for a in chain)
        n_frames = sum(1 for a in chain if frame_sizes.get(a, 0) > 0)
        print(f"  #{i+1:2d}: depth={d:5d}B (0x{d:04x}) leaf=0x{off:06x} frame={fs}B frames_in_chain={n_frames}")

    # Distribution of chain depths
    print(f"\nChain depth distribution (for PACIASP functions):")
    depth_ranges = [(856, 1024), (1024, 1536), (1536, 2048), (2048, 3072), (3072, 4096), (4096, 8192)]
    for lo, hi in depth_ranges:
        count = sum(1 for _, d in qualifying if lo <= d < hi)
        print(f"  {lo:5d}-{hi:5d}: {count:5d}")

    # Check connectivity of futex-like functions
    print(f"\n[+] Connectivity check for key frame sizes:")
    for fs_val in [0x70, 0x100, 0x120, 0x140, 0x160, 0x180, 0x1a0, 0x1c0, 0x1d0, 0x1e0, 0x1f0]:
        matches = [off for off, s in frame_sizes.items() if s == fs_val]
        if matches:
            max_d = max(depths.get(off, 0) for off in matches)
            print(f"  frame=0x{fs_val:x} ({fs_val:4d}B): {len(matches):4d} funcs, max_depth={max_d}B")

    # Print summary
    print(f"\n{'=' * 80}")
    print("FINAL SUMMARY")
    print(f"{'=' * 80}")
    print(f"Total PACIASP functions: {len(frame_sizes)}")
    print(f"Total call graph nodes (with BL edges): {len(all_nodes)}")
    print(f"Chains >= {MIN_DEPTH}B (0x{MIN_DEPTH:x}): {len(qualifying)}")
    if qualifying:
        print(f"Deepest: {qualifying[0][1]}B at 0x{qualifying[0][0]:06x}")
        print(f"Sweet spot (856-1400B): {sum(1 for _,d in qualifying if 856 <= d <= 1400)}")

if __name__ == "__main__":
    main()
