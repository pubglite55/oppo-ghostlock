#!/usr/bin/env python3
"""extract_deb.py — unpack a .deb (ar archive) without needing `ar`.

We have no `ar`/`dpkg-deb` on this host, so parse the ar format directly and then
the inner tar.  Used to get vmlinuz (kernel Image) out of a Debian kernel package
and busybox out of busybox-static.

  python extract_deb.py <file.deb> <outdir>
"""
import io, os, sys, tarfile


def read_ar(path):
    """Yield (name, bytes) for each member of an ar archive."""
    with open(path, 'rb') as f:
        data = f.read()
    if not data.startswith(b'!<arch>\n'):
        raise SystemExit('not an ar archive: %s' % path)
    off = 8
    while off + 60 <= len(data):
        hdr = data[off:off + 60]
        name = hdr[0:16].decode('ascii', 'replace').strip()
        size = int(hdr[48:58].decode('ascii', 'replace').strip() or '0')
        body = data[off + 60:off + 60 + size]
        yield name, body
        off += 60 + size + (size % 2)          # members are 2-byte aligned


def main():
    deb, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    wrote = []
    for name, body in read_ar(deb):
        if not name.startswith('data.tar'):
            continue
        with tarfile.open(fileobj=io.BytesIO(body)) as tf:
            for m in tf.getmembers():
                if not m.isfile():
                    continue
                # strip the leading ./ and any path traversal
                rel = m.name.lstrip('./')
                if '..' in rel.split('/'):
                    continue
                dst = os.path.join(outdir, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                with open(dst, 'wb') as out:
                    out.write(tf.extractfile(m).read())
                os.chmod(dst, 0o755 if ('bin/' in rel or 'vmlinuz' in rel) else 0o644)
                wrote.append((rel, m.size))
    for rel, size in wrote:
        print('%10d  %s' % (size, rel))


if __name__ == '__main__':
    main()