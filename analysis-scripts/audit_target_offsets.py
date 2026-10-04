#!/usr/bin/env python3
"""
audit_target_offsets.py — verify exploit/targets/*/target.h offsets against the
kernel image, and dump the ashmem file_operations table.

Pure stdlib (no pyelftools). Works on the vmlinux-to-elf image produced from the
device boot image (single ".kernel" section + ".symtab", imagebase in HANDOFF.md).

Usage:
    python3 analysis-scripts/audit_target_offsets.py \
        --elf output.elf \
        --target exploit/targets/oppo-find_n2/target.h

What it checks:
  1. Every data/bss symbol offset in target.h against .symtab.
  2. Every ashmem / configfs *function* offset against .symtab (this is where the
     2026-10-04 audit found a systematic one-function shift).
  3. Dumps the ashmem fops table (VA = KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
     and resolves each non-null slot to a symbol.
Exit code is 0 always; read the report.
"""
import struct, sys, bisect, os, re, argparse

DEFAULT_IMAGE_BASE = 0xffffffc008000000

# target.h macro name -> expected .symtab symbol name
SYMBOL_MAP = {
    "ASHMEM_MISC_FOPS_OFF": ("ashmem_fops", "data"),
    "ASHMEM_LLSEEK_OFF": ("ashmem_llseek", "func"),
    "ASHMEM_READ_ITER_OFF": ("ashmem_read_iter", "func"),
    "ASHMEM_IOCTL_OFF": ("ashmem_ioctl", "func"),
    "ASHMEM_COMPAT_IOCTL_OFF": ("compat_ashmem_ioctl", "func"),
    "ASHMEM_MMAP_OFF": ("ashmem_mmap", "func"),
    "ASHMEM_OPEN_OFF": ("ashmem_open", "func"),
    "ASHMEM_RELEASE_OFF": ("ashmem_release", "func"),
    "ASHMEM_SHOW_FDINFO_OFF": ("ashmem_show_fdinfo", "func"),
    "INIT_TASK_OFF": ("init_task", "data"),
    "INIT_UTS_NS_OFF": ("init_uts_ns", "data"),
    "EMPTY_ZERO_PAGE_OFF": ("empty_zero_page", "data"),
    "ROOT_TASK_GROUP_OFF": ("root_task_group", "data"),
    "SELINUX_STATE_OFF": ("selinux_state", "data"),
    "SECURITY_HOOK_HEADS_OFF": ("security_hook_heads", "data"),
    "KMALLOC_CACHES_OFF": ("kmalloc_caches", "data"),
    "ANON_PIPE_BUF_OPS_OFF": ("anon_pipe_buf_ops", "data"),
    "INIT_NET_OFF": ("init_net", "data"),
    "INIT_NSPROXY_OFF": ("init_nsproxy", "data"),
    "SELINUX_BLOB_SIZES_OFF": ("selinux_blob_sizes", "data"),
    "NOOP_LLSEEK_OFF": ("noop_llseek", "func"),
    "SLIDE_NFULNL_LOGGER_OFF": ("nfulnl_logger", "data"),
}


def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]


class Elf:
    def __init__(self, path):
        self.f = open(path, "rb")
        head = self.f.read(64)
        assert head[:4] == b"\x7fELF", "not an ELF"
        assert head[4] == 2 and head[5] == 1, "need ELF64 little-endian"
        e_shoff = u64(head, 0x28); e_shentsize = u16(head, 0x3A)
        e_shnum = u16(head, 0x3C); e_shstrndx = u16(head, 0x3E)
        self.f.seek(e_shoff); shb = self.f.read(e_shentsize * e_shnum)
        self.secs = []
        for i in range(e_shnum):
            o = i * e_shentsize
            self.secs.append(dict(
                nameoff=u32(shb, o), type=u32(shb, o + 4), flags=u64(shb, o + 8),
                addr=u64(shb, o + 0x10), off=u64(shb, o + 0x18), size=u64(shb, o + 0x20),
                link=u32(shb, o + 0x28), entsz=u64(shb, o + 0x38)))
        shstr = self.secs[e_shstrndx]
        self.f.seek(shstr["off"]); self.shstrb = self.f.read(shstr["size"])
        self.by_name = {}
        self._load_syms()

    def shname(self, n):
        e = self.shstrb.find(b"\x00", n); return self.shstrb[n:e].decode("latin1")

    def _load_syms(self):
        for st in [s for s in self.secs if s["type"] == 2] or \
                  [s for s in self.secs if s["type"] == 11]:
            strs = self.secs[st["link"]]
            self.f.seek(strs["off"]); strb = self.f.read(strs["size"])
            self.f.seek(st["off"]); raw = self.f.read(st["size"])
            es = st["entsz"] or 24
            for j in range(st["size"] // es):
                o = j * es; no = u32(raw, o); val = u64(raw, o + 8)
                if not val:
                    continue
                e = strb.find(b"\x00", no); nm = strb[no:e].decode("latin1")
                if nm:
                    self.by_name.setdefault(nm, []).append(val)
        self.addrs = sorted((v, n) for n, vs in self.by_name.items() for v in vs)
        self.keys = [a for a, _ in self.addrs]

    def sym(self, name):
        vs = self.by_name.get(name)
        return min(vs) if vs else None

    def resolve(self, va):
        i = bisect.bisect_right(self.keys, va) - 1
        if i < 0:
            return "?"
        a, nm = self.addrs[i]
        return nm if a == va else f"{nm}+0x{va - a:x}"

    def va_to_off(self, va):
        for s in self.secs:
            if s["flags"] & 2 and s["addr"] and s["addr"] <= va < s["addr"] + s["size"]:
                return s["off"] + (va - s["addr"])
        return None

    def read_va(self, va, n):
        o = self.va_to_off(va)
        if o is None:
            return None
        self.f.seek(o); return self.f.read(n)


def parse_target(path):
    vals = {}
    for line in open(path, encoding="utf-8", errors="replace"):
        m = re.match(r"\s*#define\s+([A-Z0-9_]+)_OFF\s+(0x[0-9a-fA-F]+)ULL", line)
        if m:
            vals[m.group(1) + "_OFF"] = int(m.group(2), 16)
    return vals


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", default="output.elf")
    ap.add_argument("--target", default="exploit/targets/oppo-find_n2/target.h")
    ap.add_argument("--image-base", type=lambda s: int(s, 0), default=DEFAULT_IMAGE_BASE)
    a = ap.parse_args()

    elf = Elf(a.elf)
    tgt = parse_target(a.target)
    nsec = len(elf.secs)
    print(f"[*] {a.elf}: {nsec} sections, {len(elf.by_name)} unique symbol names")
    print(f"[*] {a.target}: {len(tgt)} *_OFF defines\n")

    print("=== 1. target.h *=_OFF vs .symtab ===")
    ok = bad = miss = 0
    for macro, (sym, kind) in SYMBOL_MAP.items():
        claim = tgt.get(macro)
        v = elf.sym(sym)
        if claim is None:
            print(f"  {macro:26s} <absent from target.h>"); continue
        if v is None:
            print(f"  {macro:26s} claim=0x{claim:08x}  symbol '{sym}' <not in symtab>"); miss += 1; continue
        real = (v - a.image_base) & 0xffffffff
        good = real == claim
        ok += good; bad += (not good)
        print(f"  {macro:26s} claim=0x{claim:08x} real=0x{real:08x} ({sym})  "
              f"{'OK' if good else '*** MISMATCH ***'}")
    print(f"  -> exact={ok}  mismatch={bad}  unverifiable={miss}")

    # reverse lookups for every mismatched ashmem function claim
    if bad:
        print("\n=== 2. what the wrong ashmem function offsets actually point at ===")
        for macro, (sym, kind) in SYMBOL_MAP.items():
            if kind != "func" or macro not in tgt:
                continue
            claim = tgt[macro]; v = elf.sym(sym)
            if v is None:
                continue
            real = (v - a.image_base) & 0xffffffff
            if real != claim:
                print(f"  {macro:26s} 0x{claim:08x} (claimed {sym}) -> "
                      f"{elf.resolve(a.image_base + claim)}")

    # dump the ashmem fops table
    fops_macro = tgt.get("ASHMEM_MISC_FOPS_OFF")
    if fops_macro is not None:
        va = a.image_base + fops_macro
        print(f"\n=== 3. ashmem file_operations table @ VA 0x{va:016x} ===")
        tbl = elf.read_va(va, 0x100)
        if tbl is None:
            print("  <VA not mapped>")
        else:
            for so in range(0, 0x100, 8):
                v = u64(tbl, so)
                if v == 0:
                    continue
                tag = elf.resolve(v) if 0xffffffc000000000 <= v < 0xffffffd000000000 else "(data)"
                print(f"  +0x{so:03x}  0x{v:016x} -> {tag}")


if __name__ == "__main__":
    main()