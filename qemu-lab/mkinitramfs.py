#!/usr/bin/env python3
"""mkinitramfs.py — build a busybox initramfs as a newc cpio (.gz), pure stdlib.

No cpio on this host, so emit the newc format directly.

Expects:  <lab>/bb/busybox        (static arm64 busybox, from busybox-static .deb)
          <lab>/payload/*         (optional: files copied to /data in the guest)
Produces: <lab>/initramfs.cpio.gz

The guest init mounts proc/sys/dev, prints the kernel version + KASLR state, then
runs /data/run_exploit.sh if present and drops to a shell on the console.
"""
import gzip, os, stat, sys, time

LAB = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(LAB, 'initramfs')
BB = os.path.join(LAB, 'bb', 'busybox')
OUT = os.path.join(LAB, 'initramfs.cpio.gz')

INIT = r'''#!/bin/busybox sh
/bin/busybox mount -t proc none /proc
/bin/busybox mount -t sysfs none /sys
/bin/busybox mount -t devtmpfs none /dev 2>/dev/null
/bin/busybox mount -t debugfs none /sys/kernel/debug 2>/dev/null
echo "================ QEMU LAB UP ================"
cat /proc/version
echo "cmdline: $(cat /proc/cmdline)"
echo "kaslr/randomize_va_space: $(cat /proc/sys/kernel/randomize_va_space)"
echo "cmdline nokaslr: $(grep -c nokaslr /proc/cmdline)"
echo "perf_event_paranoid: $(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)"
echo "futex PI: $(grep -c FUTEX /proc/config.gz 2>/dev/null || echo n/a)"
ls -d /sys/fs/selinux 2>/dev/null || echo "selinux: not enabled in this kernel"
echo "---------------------------------------------"
if [ -x /data/run_exploit.sh ]; then
  echo ">>> running /data/run_exploit.sh"
  /data/run_exploit.sh
  echo ">>> rc=$?"
else
  echo "(no /data/run_exploit.sh)"
fi
echo "================ DROPPING TO SHELL =========="
exec /bin/busybox sh
'''


def write_cpio(path, entries):
    out = open(path, 'wb')

    def hdr(name, mode, size, ino, nlink):
        namez = name.encode() + b'\0'
        # newc header, 13 fields after the magic:
        # ino, mode, uid, gid, nlink, mtime, filesize, devmajor, devminor,
        # rdevmajor, rdevminor, namesize, check
        fields = [ino, mode, 0, 0, nlink, 0, size, 0, 0, 0, 0, len(namez), 0]
        body = b'070701' + b''.join(b'%08x' % f for f in fields) + namez
        pad = (-len(body)) % 4
        out.write(body + b'\0' * pad)

    ino = 1
    for name, data, mode in entries:
        if name.endswith('/'):                 # directory: S_IFDIR, nlink=2, no data
            hdr(name, 0o040755, 0, ino, 2)
            ino += 1
            continue
        hdr(name, mode, len(data), ino, 1)
        ino += 1
        out.write(data)
        out.write(b'\0' * ((-len(data)) % 4))
    # trailer
    hdr('TRAILER!!!', 0, 0, ino, 1)
    out.close()


def main():
    if not os.path.exists(BB):
        sys.exit('missing %s (extract busybox-static-arm64.deb first)' % BB)

    F = 0o100644
    X = 0o100755
    # Prefer the compiled static init (no busybox / no shebang needed); fall back
    # to the busybox script if init.bin is absent.
    initbin = os.path.join(LAB, 'init.bin')
    if os.path.exists(initbin):
        with open(initbin, 'rb') as f:
            entries = [('init', f.read(), X)]
    else:
        entries = [('init', INIT.encode(), X)]
    # busybox + applet symlinks
    with open(BB, 'rb') as f:
        entries.append(('bin/busybox', f.read(), X))
    for app in ('sh mount umount cat ls ps grep dmesg sleep echo id cp chmod mknod '
                'insmod rm mkdir true false find head tail wc cut tee date printf '
                'setsid poweroff reboot').split():
        entries.append(('bin/' + app, b'/bin/busybox', 0o120777))   # symlink
    for d in ('proc', 'sys', 'dev', 'tmp', 'data', 'sys/kernel', 'sys/kernel/debug'):
        entries.append((d + '/', b'', 0o040755))

    # optional payload -> /data (so the exploit + its runner ride along)
    pay = os.path.join(LAB, 'payload')
    if os.path.isdir(pay):
        for fn in sorted(os.listdir(pay)):
            p = os.path.join(pay, fn)
            if os.path.isfile(p):
                with open(p, 'rb') as f:
                    entries.append(('data/' + fn, f.read(), X))

    write_cpio(OUT, entries)
    print('wrote %s (%.1f KiB, %d entries)' % (OUT, os.path.getsize(OUT) / 1024.0, len(entries)))
    # also keep an uncompressed copy for inspection
    with open(OUT, 'rb') as f:
        raw = f.read()
    with gzip.open(OUT, 'wb', compresslevel=9) as g:
        g.write(raw)


if __name__ == '__main__':
    main()