#!/usr/bin/env python3
"""Apply smb-kawari.patch to the original "super m. bros.64" PRG.

    python3 apply_patch.py "super m. bros.64" smb-kawari.patch smb-kawari.prg

The original PRG is a small loader followed by two LZ-packed images.  Almost
every packed byte changes when the game image is edited, so a byte-level diff
of the two PRGs would have to carry most of the (re-packed) game.  This patch
works one level down instead and holds only the real differences:

  1. the game image (payload 2) is unpacked from the original PRG,
  2. the patch's IMAGE records are written over the unpacked image,
  3. the image is packed again and the loader constants that depend on the
     packed size are recomputed,
  4. the patch's FILE records are written over (and appended to) the result.

Both ends are checked with SHA-256, so the output is either byte-exact or the
script fails without writing anything.  Needs Python 3.6+, nothing else.

Patch file layout (all integers little-endian):

    8   magic "SMBKWR1\\0"
    32  SHA-256 of the original PRG
    32  SHA-256 of the patched PRG
    2   number of IMAGE records     (offsets into the unpacked 63463-byte image)
    ..  records: u16 offset, u16 length, <length> bytes
    2   number of FILE records      (offsets into the re-packed PRG file; a
    ..  records: same form           record may extend the file)
"""

import hashlib
import struct
import sys

MAGIC = b"SMBKWR1\0"

LOAD = 0x0801                  # PRG load address
P2_ADDR = 0x0EF1               # payload 2 (the game image) in the file
P2_SIZE = 39388                # its packed size in the original
P1_SIZE = 7399                 # payload 1 (the front end), last in the file
P1_PASSES = 29
STAGE2_RELOC = 0x0A38          # file address = run-time address + $0A38
OUT_SIZE = 0xFFE8 - LOAD       # the unpacked game image: 63463 bytes
DIST_TABLE = bytes([0xDF, 0xFB, 0x00, 0x80, 0xEF, 0xFD, 0x80, 0xF0])
MAX_RUN = 255
MIN_MATCH = 2


# ---------------------------------------------------------------------------
# unpacker
# ---------------------------------------------------------------------------

def unpack(p):
    """Expand a packed stream; returns (destination address, bytes)."""
    pos = 2
    fd = 0
    dest = p[0] | p[1] << 8
    out = bytearray()

    def raw():
        nonlocal pos
        pos += 1
        return p[pos - 1]

    def refill():
        nonlocal fd
        b = raw()
        fd = ((b << 1) | 1) & 0xFF
        return b >> 7

    def bit():
        nonlocal fd
        c = fd >> 7
        fd = (fd << 1) & 0xFF
        return refill() if fd == 0 else c

    def count(stop):
        a = 1
        if bit() == 0:
            return a
        while True:
            a = ((a << 1) | bit()) & 0xFF
            if bit() == stop:
                return a

    def low(a, ptr):
        y = ~a & 0xFF
        r = raw()
        s = r + (ptr & 0xFF)
        return (((y + (ptr >> 8) + (s >> 8)) & 0xFF) << 8) | (s & 0xFF)

    def source(carry, ptr):
        a = 0x80 | carry
        a = ((a << 1) | bit()) & 0xFF
        a = ((a << 1) | bit()) & 0xFF
        a = DIST_TABLE[a]
        if a == 0:
            return low(a, ptr)
        while True:
            b = bit()
            c = a >> 7
            a = ((a << 1) | b) & 0xFF
            if c == 0:
                break
        if a & 0x80:
            s = a + (ptr & 0xFF)
            return (((0xFF + (ptr >> 8) + (s >> 8)) & 0xFF) << 8) | (s & 0xFF)
        return low(a, ptr)

    sel = refill()
    while True:
        if sel:
            for _ in range(count(0)):
                out.append(raw())
        n = count(1)
        if n == 0:
            return dest, bytes(out)
        ptr = dest + len(out)
        src = source(1 if n > 1 else 0, ptr) - dest
        for i in range(n + 1):
            out.append(out[src + i])
        sel = bit()


# ---------------------------------------------------------------------------
# packer
# ---------------------------------------------------------------------------

def lit_count_bits(n):
    if n == 1:
        return [0]
    bits = [1]
    for i in range(n.bit_length() - 2, -1, -1):
        bits += [(n >> i) & 1, 1 if i > 0 else 0]
    return bits


def match_count_bits(n):
    if n == 0:
        return [1] + [0, 0] * 7 + [0, 1]
    if n == 1:
        return [0]
    bits = [1]
    for i in range(n.bit_length() - 2, -1, -1):
        bits += [(n >> i) & 1, 0 if i > 0 else 1]
    return bits


class Writer:
    def __init__(self):
        self.out = bytearray()
        self.idx = self.pos = self.left = 0

    def raw(self, v):
        self.out.append(v & 0xFF)

    def bit(self, v):
        if self.left == 0:
            self.out.append((v & 1) << 7)
            self.idx, self.pos, self.left = len(self.out) - 1, 6, 7
        else:
            self.out[self.idx] |= (v & 1) << self.pos
            self.pos -= 1
            self.left -= 1

    def bits(self, vs):
        for v in vs:
            self.bit(v)


def _try_entry(entry, head, olo, ohi, slo, shi):
    raw = (slo - olo) & 0xFF
    cy = 1 if raw + olo > 0xFF else 0
    if entry == 0:
        return (head, raw) if ((0xFF + ohi + cy) & 0xFF) == shi else None
    k = 8
    for i in range(1, 9):
        if not (entry >> (8 - i)) & 1:
            k = i
            break
    base = (entry << k) & 0xFF
    mask = (1 << k) - 1
    vbits = lambda v: [(v >> i) & 1 for i in range(k - 1, -1, -1)]
    if (raw & 0x80) and (raw & ~mask & 0xFF) == base \
            and ((0xFF + ohi + cy) & 0xFF) == shi:
        return head + vbits(raw & mask), None
    a2 = ~((shi - ohi - cy) & 0xFF) & 0xFF
    if not (a2 & 0x80) and (a2 & ~mask & 0xFF) == base:
        return head + vbits(a2 & mask), raw
    return None


def encode_distance(distance, out_ptr, n):
    carry = 0 if n == 1 else 1
    src = (out_ptr - distance) & 0xFFFF
    for b1 in (0, 1):
        for b2 in (0, 1):
            got = _try_entry(DIST_TABLE[4 * carry + 2 * b1 + b2], [b1, b2],
                             out_ptr & 0xFF, out_ptr >> 8, src & 0xFF, src >> 8)
            if got is not None:
                return got
    return None


class Matcher:
    def __init__(self, data, chain=256):
        self.d = data
        self.chain = chain
        self.head = {}
        self.prev = [0] * (len(data) + 1)

    def insert(self, i):
        if i + 2 > len(self.d):
            return
        k = (self.d[i] << 8) | self.d[i + 1]
        self.prev[i] = self.head.get(k, -1)
        self.head[k] = i

    def find(self, i, limit, out_ptr):
        d = self.d
        if i + 2 > len(d):
            return 0, 0
        best_len = best_dist = 0
        j = self.head.get((d[i] << 8) | d[i + 1], -1)
        tries = self.chain
        while j >= 0 and tries > 0:
            dist = i - j
            if dist > 0xFFFF:
                break
            n = 0
            while n < limit and d[j + n] == d[i + n]:
                n += 1
            if n > best_len and n >= MIN_MATCH \
                    and encode_distance(dist, out_ptr, n - 1) is not None:
                best_len, best_dist = n, dist
                if n >= limit:
                    break
            j = self.prev[j]
            tries -= 1
        return best_len, best_dist


def pack(image, dest, src_addr):
    """Pack *image* for expansion to *dest* while being read at *src_addr*."""
    n = len(image)
    m = Matcher(image)
    w = Writer()
    w.raw(dest & 0xFF)
    w.raw(dest >> 8)
    out_pos = dest
    margin = tightest = src_addr - out_pos
    pending = bytearray()
    i = 0

    def emit(literals, match):
        nonlocal out_pos, margin, tightest
        w.bit(1 if literals else 0)
        if literals:
            w.bits(lit_count_bits(len(literals)))
            for b in literals:
                w.raw(b)
        if match is None:
            w.bits(match_count_bits(0))
        else:
            bits, raw = encode_distance(match[1], out_pos, match[0] - 1)
            w.bits(match_count_bits(match[0] - 1))
            w.bits(bits)
            if raw is not None:
                w.raw(raw)
        out_pos += len(literals) + (match[0] if match else 0)
        margin = (src_addr + len(w.out)) - out_pos
        tightest = min(tightest, margin)

    while i < n:
        length, dist = m.find(i, min(MAX_RUN, n - i), out_pos)
        affordable = (margin - 4) >= length
        if length >= MIN_MATCH and affordable and len(pending) < MAX_RUN:
            if i + 1 < n:
                l2, _ = m.find(i + 1, min(MAX_RUN, n - i - 1), out_pos + 1)
                if l2 > length and (margin - 4 - 1) >= l2:
                    pending.append(image[i])
                    m.insert(i)
                    i += 1
                    continue
        elif len(pending) == MAX_RUN:
            length, dist = m.find(i, min(MAX_RUN, n - i), out_pos)
            if length < MIN_MATCH:
                raise SystemExit("cannot break a 255-byte literal run")
        else:
            pending.append(image[i])
            m.insert(i)
            i += 1
            continue
        emit(bytes(pending), (length, dist))
        pending.clear()
        for k in range(length):
            m.insert(i + k)
        i += length
    emit(bytes(pending), None)
    if tightest < 0:
        raise SystemExit("expansion would overwrite unread source")
    return bytes(w.out)


# ---------------------------------------------------------------------------
# loader layout
# ---------------------------------------------------------------------------

def fit_read_addr(s2):
    passes = (s2 + 255) // 256
    a2 = s2 - 1 - (passes - 1) * 256
    cand = 0xFFF8 - s2
    while (cand & 0xFF) + a2 > 0xFF:
        cand -= 1
        if cand < LOAD + OUT_SIZE - s2:
            return None
    return cand


def repack(image):
    """Returns (payload, read address), iterated to a fixed point."""
    src = 0x661C
    for _ in range(5):
        payload = pack(image, LOAD, src)
        while fit_read_addr(len(payload)) is None:
            payload += b"\0"
        cand = fit_read_addr(len(payload))
        if cand == src:
            break
        src = cand
    return payload, src


def patch_loader(head, s2, src):
    buf = bytearray(head)
    passes = (s2 + 255) // 256
    a2 = s2 - 1 - (passes - 1) * 256
    top_hi = (src >> 8) + passes - 1
    s2base = P2_ADDR + (passes - 1) * 256
    s1base = P2_ADDR + s2 + (P1_PASSES - 1) * 256

    def put(addr, value):
        buf[addr - LOAD + 2] = value & 0xFF

    for rt, v in ((0x0202, a2), (0x0206, s2base), (0x0207, s2base >> 8),
                  (0x0209, src), (0x020A, top_hi), (0x020F, s2base),
                  (0x0210, s2base >> 8), (0x0212, src), (0x0213, top_hi),
                  (0x0225, src >> 8), (0x0229, src), (0x022B, src >> 8)):
        put(rt + STAGE2_RELOC, v)
    for addr, v in ((0x08A5, s1base), (0x08A6, s1base >> 8),
                    (0x08AE, s1base), (0x08AF, s1base >> 8)):
        put(addr, v)
    return bytes(buf)


# ---------------------------------------------------------------------------
# patch records
# ---------------------------------------------------------------------------

def read_records(patch, pos):
    (count,) = struct.unpack_from("<H", patch, pos)
    pos += 2
    recs = []
    for _ in range(count):
        off, ln = struct.unpack_from("<HH", patch, pos)
        pos += 4
        recs.append((off, patch[pos:pos + ln]))
        pos += ln
    return recs, pos


def apply_records(data, recs):
    buf = bytearray(data)
    for off, chunk in recs:
        if off > len(buf):
            raise SystemExit("patch record at %d is past the end" % off)
        buf[off:off + len(chunk)] = chunk
    return bytes(buf)


def apply(orig, patch):
    if patch[:8] != MAGIC:
        raise SystemExit("not an smb-kawari patch file")
    if hashlib.sha256(orig).digest() != patch[8:40]:
        raise SystemExit("the input is not the expected original PRG "
                         "(SHA-256 mismatch) - nothing written")
    image_recs, pos = read_records(patch, 72)
    file_recs, pos = read_records(patch, pos)

    p2 = P2_ADDR - LOAD + 2
    head = orig[:p2]
    payload1 = orig[len(orig) - P1_SIZE:]
    dest, image = unpack(orig[p2:p2 + P2_SIZE])
    if dest != LOAD or len(image) != OUT_SIZE:
        raise SystemExit("the game image did not unpack as expected")

    image = apply_records(image, image_recs)
    payload2, src = repack(image)
    prg = patch_loader(head, len(payload2), src) + payload2 + payload1
    prg = apply_records(prg, file_recs)

    if hashlib.sha256(prg).digest() != patch[40:72]:
        raise SystemExit("the result does not match the patch's checksum "
                         "- nothing written")
    return prg


def main(argv):
    if len(argv) != 4:
        print(__doc__)
        return 2
    orig = open(argv[1], "rb").read()
    patch = open(argv[2], "rb").read()
    prg = apply(orig, patch)
    with open(argv[3], "wb") as f:
        f.write(prg)
    print("wrote %s: %d bytes, SHA-256 %s"
          % (argv[3], len(prg), hashlib.sha256(prg).hexdigest()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
