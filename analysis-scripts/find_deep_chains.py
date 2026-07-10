#!/usr/bin/env python3
"""Find syscall call chains with total stack depth >= 856 bytes (0x358) in vmlinux.elf."""

import struct
from elftools.elf.elffile import ELFFile
from collections import defaultdict

VMLINUX = "/Users/xiuxiu391/Desktop/oppo/vmlinux.elf"
MIN_DEPTH = 0x358  # 856 bytes
MIN_FRAME = 0x100  # Only care about large frames for tracing

def load_text_section():
    with open(VMLINUX, "rb") as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name(".text")
        if text is None:
            raise RuntimeError("No .text section")
        offset = text["sh_offset"]
        size = text["sh_size"]
        vaddr = text["sh_addr"]
        f.seek(offset)
        data = f.read(size)
    print(f"[+] .text: vaddr=0x{vaddr:x}, size=0x{size:x}, offset=0x{offset:x}")
    return data, vaddr

def find_functions(data, vaddr):
    """Find function prologues: PACIASP (0xD503233F) followed by SUB SP,SP,#imm."""
    funcs = {}  # addr -> frame_size
    i = 0
    while i + 7 < len(data):
        inst = struct.unpack_from("<I", data, i)[0]
        if inst == 0xD503233F:  # PACIASP
            # Check next instruction for SUB SP,SP,#imm
            next_inst = struct.unpack_from("<I", data, i + 4)[0]
            if (next_inst & 0xFFC003FF) == 0xD10003FF:  # SUB SP,SP,#imm
                # Decode imm: bits [21:10] = imm12, shifted left by 12
                imm12 = (next_inst >> 10) & 0xFFF
                frame_size = imm12 << 12
                func_addr = vaddr + i
                funcs[func_addr] = frame_size
                i += 8
                continue
        i += 4
    return funcs

def build_bl_map(data, vaddr, text_start):
    """Build mapping: caller_addr -> list of callee_addrs via BL instructions."""
    bl_map = defaultdict(list)
    for i in range(0, len(data) - 3, 4):
        inst = struct.unpack_from("<I", data, i)[0]
        if (inst >> 26) == 0x25:  # BL instruction
            imm26 = inst & 0x3FFFFFF
            # Sign extend 26-bit
            if imm26 & 0x2000000:
                imm26 |= ~0x3FFFFFF
                imm26 = imm26 & 0xFFFFFFFF
                imm26 = imm26 - (1 << 32)
            target = vaddr + i + imm26 * 4
            caller = vaddr + i
            bl_map[caller].append(target)
    return bl_map

def find_syscalls(funcs, bl_map):
    """Find sys_* functions and trace their call chains."""
    syscalls = {}
    for addr, frame in funcs.items():
        # Get function name from symbol if possible, or check address range
        syscalls[addr] = frame
    return syscalls

def trace_chains(funcs, bl_map, min_depth):
    """Trace call chains from all functions, find those with total depth >= min_depth."""
    # Build reverse map: callee -> [callers]
    rev_map = defaultdict(list)
    for caller, callees in bl_map.items():
        for callee in callees:
            rev_map[callee].append(caller)

    # Build forward map for outgoing calls (filtered to functions we know)
    func_set = set(funcs.keys())

    # For each function, trace backward to find root (functions not called by others in our set)
    def get_chain_depth(addr, visited=None):
        """Get max depth of call chain ending at addr."""
        if visited is None:
            visited = set()
        if addr in visited:
            return 0
        visited = visited | {addr}

        frame = funcs.get(addr, 0)
        callers = rev_map.get(addr, [])

        # Filter callers to only those that have BL to us and are in our func set
        valid_callers = [c for c in callers if c in func_set]

        if not valid_callers:
            return frame

        max_caller_depth = 0
        best_caller = None
        for c in valid_callers:
            d = get_chain_depth(c, visited)
            if d > max_caller_depth:
                max_caller_depth = d
                best_caller = c

        return frame + max_caller_depth

    # Find all chains with depth >= min_depth
    results = []
    for addr in funcs:
        if funcs[addr] >= MIN_FRAME:  # Only trace from large-frame functions
            depth = get_chain_depth(addr)
            if depth >= min_depth:
                results.append((addr, depth))

    results.sort(key=lambda x: -x[1])
    return results

def build_full_chains(funcs, bl_map, target_addrs, min_depth):
    """For each target address, build the actual call chain."""
    func_set = set(funcs.keys())
    rev_map = defaultdict(list)
    for caller, callees in bl_map.items():
        for callee in callees:
            rev_map[callee].append(caller)

    chains = []
    for target_addr in target_addrs:
        chain = []
        visited = set()

        def build_chain(addr):
            if addr in visited:
                return
            visited.add(addr)
            frame = funcs.get(addr, 0)
            callers = rev_map.get(addr, [])
            valid_callers = [c for c in callers if c in func_set]

            chain.append((addr, frame))

            if valid_callers:
                # Pick the caller that gives max depth
                best = max(valid_callers, key=lambda c: get_depth(c))
                build_chain(best)

        def get_depth(addr, vis=None):
            if vis is None:
                vis = set()
            if addr in vis:
                return 0
            vis = vis | {addr}
            frame = funcs.get(addr, 0)
            callers = [c for c in rev_map.get(addr, []) if c in func_set]
            if not callers:
                return frame
            return frame + max(get_depth(c, vis) for c in callers)

        build_chain(target_addr)
        chain.reverse()  # root -> leaf order

        total_depth = sum(f for _, f in chain)
        if total_depth >= min_depth:
            chains.append((chain, total_depth))

    return chains

def main():
    print("=" * 80)
    vmlinux_data, vmlinux_vaddr = load_text_section()

    # Get actual .text base from ELF
    with open(VMLINUX, "rb") as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name(".text")
        text_base = text["sh_addr"]

    print(f"[+] Scanning for PACIASP+SUB SP patterns...")
    funcs = find_functions(vmlinux_data, text_base)
    print(f"[+] Found {len(funcs)} functions with PACIASP prologues")

    # Show frame size distribution
    sizes = sorted(set(funcs.values()), reverse=True)
    print(f"[+] Unique frame sizes: {len(sizes)}")
    print(f"[+] Largest frames:")
    large = [(a, s) for a, s in funcs.items() if s >= 0x100]
    large.sort(key=lambda x: -x[1])
    for addr, size in large[:30]:
        print(f"    0x{addr:x}: frame=0x{size:x} ({size} bytes)")

    print(f"\n[+] Building BL call graph...")
    bl_map = build_bl_map(vmlinux_data, text_base, text_base)
    total_bls = sum(len(v) for v in bl_map.values())
    print(f"[+] Found {len(bl_map)} functions with BL calls, {total_bls} total BL instructions")

    print(f"\n[+] Tracing call chains (min depth = 0x{MIN_DEPTH:x})...")
    # Only consider functions with frame >= 0x80 for efficiency
    large_funcs = {a: s for a, s in funcs.items() if s >= 0x80}
    print(f"[+] Functions with frame >= 0x80: {len(large_funcs)}")

    # Build reverse map
    rev_map = defaultdict(list)
    func_set = set(funcs.keys())
    for caller, callees in bl_map.items():
        for callee in callees:
            if callee in func_set:
                rev_map[callee].append(caller)

    def get_depth(addr, vis=None):
        if vis is None:
            vis = set()
        if addr in vis:
            return 0
        vis = vis | {addr}
        frame = funcs.get(addr, 0)
        callers = rev_map.get(addr, [])
        if not callers:
            return frame
        return frame + max(get_depth(c, vis) for c in callers)

    # Find chains
    candidates = []
    for addr, frame in funcs.items():
        if frame >= 0x80:
            d = get_depth(addr)
            if d >= MIN_DEPTH:
                candidates.append((addr, frame, d))

    candidates.sort(key=lambda x: -x[2])
    print(f"[+] Found {len(candidates)} chains with depth >= 0x{MIN_DEPTH:x}")

    # Build full chains for top candidates
    top_targets = [c[0] for c in candidates[:50]]
    chains = build_full_chains(funcs, bl_map, top_targets, MIN_DEPTH)

    # Deduplicate
    seen = set()
    unique_chains = []
    for chain, depth in chains:
        key = tuple(a for a, _ in chain)
        if key not in seen:
            seen.add(key)
            unique_chains.append((chain, depth))

    unique_chains.sort(key=lambda x: -x[1])

    # Report
    print(f"\n{'=' * 80}")
    print(f"CALL CHAINS WITH TOTAL STACK DEPTH >= 0x{MIN_DEPTH:x} ({MIN_DEPTH} bytes)")
    print(f"{'=' * 80}")

    for i, (chain, depth) in enumerate(unique_chains[:30]):
        print(f"\n--- Chain #{i+1}: total depth = 0x{depth:x} ({depth} bytes) ---")
        for addr, frame in chain:
            print(f"    0x{addr:x}: frame=0x{frame:x} ({frame} bytes)")
        print(f"    [Depth check: 0x{depth:x} >= 0x{MIN_DEPTH:x} = {depth >= MIN_DEPTH}]")

    # Also specifically check known syscalls
    print(f"\n{'=' * 80}")
    print("KNOWN SYSCALL ANALYSIS")
    print(f"{'=' * 80}")

    # Find functions matching known syscall names by looking at strings
    known = {
        "futex": [],
        "select": [],
        "pselect": [],
        "epoll": [],
        "poll": [],
        "recvmsg": [],
        "sendmsg": [],
        "socket": [],
        "setsockopt": [],
        "getsockopt": [],
        "bind": [],
        "listen": [],
        "accept": [],
        "connect": [],
        "readv": [],
        "writev": [],
        "preadv": [],
        "pwritev": [],
        "io_uring": [],
        "uring": [],
        "ioctl": [],
        "fcntl": [],
        "openat": [],
        "close": [],
        "dup3": [],
        "pipe2": [],
        "eventfd2": [],
        "signalfd4": [],
        "timerfd_create": [],
        "inotify_init1": [],
        "perf_event_open": [],
        "bpf": [],
        "mount": [],
        "pivot_root": [],
        "move_mount": [],
        "fanotify_init": [],
        "name_to_handle_at": [],
    }

    # Find sys_* by scanning for functions that reference "sys_" strings or use known patterns
    # Also check for __arm64_sys_* which are the actual syscall wrappers

    # Let's check what we can find by looking at all functions and their depths
    # Focus on functions with frame sizes matching known syscall patterns
    print(f"\nSearching for syscall-like frame sizes (0x60-0x400)...")

    syscall_candidates = []
    for addr, frame in funcs.items():
        if 0x60 <= frame <= 0x400:
            d = get_depth(addr)
            if d >= MIN_DEPTH:
                syscall_candidates.append((addr, frame, d))

    syscall_candidates.sort(key=lambda x: -x[2])
    print(f"Found {len(syscall_candidates)} candidates")

    for addr, frame, depth in syscall_candidates[:20]:
        print(f"  0x{addr:x}: own_frame=0x{frame:x}, chain_depth=0x{depth:x} ({depth} bytes)")

    # Try to identify syscall functions by looking for patterns
    # __arm64_sys_* functions typically have small frames and call do_* functions
    print(f"\n[+] Searching for __arm64_sys_* pattern (small frame calling larger functions)...")
    small_frame_funcs = [(a, s) for a, s in funcs.items() if 0x20 <= s <= 0x100]
    print(f"[+] Functions with frame 0x20-0x100: {len(small_frame_funcs)}")

    # Find BL targets from small-frame functions
    for addr, frame in small_frame_funcs:
        callees = bl_map.get(addr, [])
        for callee in callees:
            if callee in funcs and funcs[callee] >= 0x100:
                d = get_depth(callee) + frame
                if d >= MIN_DEPTH:
                    print(f"  Possible syscall wrapper 0x{addr:x} (frame=0x{frame:x}) -> callee 0x{callee:x} (frame=0x{funcs[callee]:x}), chain=0x{d:x}")

    print(f"\n{'=' * 80}")
    print("SUMMARY")
    print(f"{'=' * 80}")
    print(f"Total functions with PACIASP prologue: {len(funcs)}")
    print(f"Total chains >= 0x{MIN_DEPTH:x}: {len(unique_chains)}")
    if unique_chains:
        print(f"\nTop 10 deepest chains:")
        for i, (chain, depth) in enumerate(unique_chains[:10]):
            print(f"  #{i+1}: depth=0x{depth:x} ({depth}B), {len(chain)} frames")
            for addr, frame in chain:
                print(f"        0x{addr:x}: 0x{frame:x}")

if __name__ == "__main__":
    main()
