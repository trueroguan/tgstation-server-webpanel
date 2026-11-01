import gzip
import io
import json
import lzma
import math
import os
import struct
import zlib

try:
    from compression import zstd
except ImportError:
    zstd = None

M32 = 0xFFFFFFFF
C2S = 0
S2C = 1
MAX_TYPE = 0x101
MAX_LEN = 0x4000000
RESYNC_MAX_LEN = 0x10000
MAX_DEFERRED = 256
MAX_DEFERRED_BYTES = 1 << 22
MAGIC = b"BYCAP1\n"
BAD = 2
REDACTED = 4
BULK = 8
DROPPED = REDACTED | BULK
REDACT_C2S = frozenset({26})
KEEP_C2S = frozenset({1})
BULK_LIMITS = {114: 4096, 158: 4096, 159: 4096}
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
GZIP_MAGIC = b"\x1f\x8b"
XZ_MAGIC = b"\xfd7zXZ\x00"
MAX_META = 1 << 20
WRITE_BATCH = 1 << 16
READ_BUFFER = 1 << 20
DEFERRED = object()
_O_BINARY = getattr(os, "O_BINARY", 0)
_STREAM_ERRORS = (EOFError, struct.error, ValueError, zlib.error, lzma.LZMAError, OSError) + (
    (zstd.ZstdError,) if zstd is not None else ())


class SessionError(ValueError):
    pass


def _crc_table():
    table = []
    for i in range(256):
        c = i << 24
        for _ in range(8):
            c = ((c << 1) ^ 0xAF) & M32 if c & 0x80000000 else (c << 1) & M32
        table.append(c)
    return table


CRC_TABLE = _crc_table()


def content_key(data):
    c = M32
    t = CRC_TABLE
    for b in data:
        c = ((c << 8) & M32) ^ t[((c >> 24) ^ b) & 0xFF]
    return c


def key_stream(key):
    return [(key >> i) & 0xFF for i in range(32)]


def decrypt_with(body, ks):
    n = len(body) - 1
    if n < 0:
        return b"", False
    out = bytearray(n)
    s = 0
    for i in range(n):
        nxt = (body[i] - ks[s & 31]) & 0xFF
        out[i] = (nxt - s) & 0xFF
        s = nxt
    return bytes(out), body[n] == s


def decrypt(body, key):
    return decrypt_with(body, key_stream(key))


def session_key0(version, build, seed):
    return (seed + (build << 16) + version) & M32


def seq_next(seq):
    seq = (seq * 0x43D4) % 0xFFF1
    return seq or 1


def reply_fold(plain):
    p = 11
    while True:
        w = struct.unpack_from("<I", plain, p)[0]
        p += 4
        if ((w + 1908237103) & 0x4008000) == 0:
            break
    return struct.unpack_from("<I", plain, p)[0]


class Half:
    __slots__ = ("side", "buf", "frames", "seq", "lost")

    def __init__(self, side):
        self.side = side
        self.buf = bytearray()
        self.frames = 0
        self.seq = None
        self.lost = False


class Link:
    def __init__(self):
        self.key0 = None
        self.key1 = None
        self._ks0 = None
        self._ks1 = None
        self.version = 0
        self.build = 0
        self.client_version = 0
        self.client_build = 0
        self.halves = (Half(C2S), Half(S2C))
        self.bad = 0
        self.resyncs = 0
        self.deferred = []
        self.deferred_bytes = 0
        self.failed = False

    def ready(self):
        return self.key1 is not None

    def buffered(self):
        return len(self.halves[0].buf) + len(self.halves[1].buf) + self.deferred_bytes

    def feed(self, side, data):
        if self.failed:
            return []
        h = self.halves[side]
        h.buf += data
        out = []
        while True:
            m = self._one(h)
            if m is None:
                break
            if m is DEFERRED:
                if self.failed:
                    h.buf.clear()
                    break
                continue
            out.append(m)
            if self.deferred and self._ks1 is not None:
                ks = self._ks1
                for mt, body in self.deferred:
                    plain, ok = decrypt_with(body, ks)
                    if not ok:
                        self.bad += 1
                    out.append((C2S, mt, plain, ok))
                self.deferred = []
                self.deferred_bytes = 0
        return out

    def gap(self, side):
        h = self.halves[side]
        h.buf.clear()
        h.lost = True
        h.seq = None

    def _peek(self, h, at):
        b = h.buf
        p = at
        seq = None
        if h.side == C2S and h.frames > 0:
            if len(b) < p + 2:
                return None
            seq = struct.unpack_from(">H", b, p)[0]
            p += 2
        if len(b) < p + 4:
            return None
        w0, w1 = struct.unpack_from(">HH", b, p)
        p += 4
        if w0 == 0xA0 and w1 == 0x0006:
            if len(b) < p + 6:
                return None
            mt, ln = struct.unpack_from(">HI", b, p)
            p += 6
        else:
            mt, ln = w0, w1
        return p - at, seq, mt, ln

    def _plausible(self, h, seq, mt, ln):
        if mt > MAX_TYPE or ln > MAX_LEN:
            return False
        if seq is not None and h.seq is not None and seq != seq_next(h.seq):
            return False
        return True

    def _stream_for(self, side, mt):
        if side == S2C and mt == 1 and self._ks1 is None:
            return self._ks0
        return self._ks1 if self._ks1 is not None else self._ks0

    def _one(self, h):
        if h.lost:
            return self._resync(h)
        r = self._peek(h, 0)
        if r is None:
            return None
        hdr, seq, mt, ln = r
        if not self._plausible(h, seq, mt, ln):
            h.lost = True
            return self._resync(h)
        if len(h.buf) < hdr + ln:
            return None
        body = bytes(h.buf[hdr:hdr + ln])
        del h.buf[:hdr + ln]
        return self._accept(h, seq, mt, body)

    def _accept(self, h, seq, mt, body):
        side = h.side
        if side == C2S and h.frames == 0:
            if mt == 1 and len(body) >= 12:
                v, b, s = struct.unpack_from("<III", body, 0)
                self.client_version, self.client_build = v, b
                self.key0 = session_key0(v, b, s)
                self._ks0 = key_stream(self.key0)
            plain, ok = body, True
        elif side == C2S and self.key1 is None and self.key0 is not None:
            if seq is not None:
                h.seq = seq
            h.frames += 1
            self.deferred.append((mt, body))
            self.deferred_bytes += len(body)
            if len(self.deferred) > MAX_DEFERRED or self.deferred_bytes > MAX_DEFERRED_BYTES:
                self.failed = True
            return DEFERRED
        else:
            ks = self._stream_for(side, mt)
            if ks is None:
                plain, ok = b"", False
            else:
                plain, ok = decrypt_with(body, ks)
            if ok and side == S2C and mt == 1 and self.key1 is None and len(plain) >= 15:
                try:
                    self.version, self.build = struct.unpack_from("<II", plain, 0)
                    self.key1 = (self.key0 + reply_fold(plain)) & M32
                    self._ks1 = key_stream(self.key1)
                except struct.error:
                    ok = False
        if seq is not None:
            h.seq = seq
        h.frames += 1
        if not ok:
            self.bad += 1
        return side, mt, plain, ok

    def _resync(self, h):
        if self._ks1 is None:
            return None
        b = h.buf
        limit = len(b) - 6
        at = 0
        while at < limit:
            r = self._peek(h, at)
            if r is None:
                return None
            hdr, seq, mt, ln = r
            if ln and mt <= MAX_TYPE and ln <= RESYNC_MAX_LEN:
                if len(b) < at + hdr + ln:
                    if at > 0:
                        del b[:at]
                    return None
                plain, ok = decrypt_with(bytes(b[at + hdr:at + hdr + ln]), self._ks1)
                if ok:
                    del b[:at + hdr + ln]
                    h.lost = False
                    self.resyncs += 1
                    if seq is not None:
                        h.seq = seq
                    h.frames += 1
                    return h.side, mt, plain, ok
            at += 1
        if limit > 0:
            del b[:limit]
        return None


def varint(n):
    out = bytearray()
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def _start_of(meta):
    for name in ("start", "startedAt"):
        v = meta.get(name)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v):
            return float(v)
    return None


class SessionWriter:
    def __init__(self, path, meta, client_input=False):
        self.path = os.fspath(path)
        self.meta = dict(meta)
        start = _start_of(self.meta)
        if start is None:
            raise ValueError("session meta needs a numeric start")
        self.meta["start"] = start
        self.client_input = bool(client_input)
        head = json.dumps(self.meta, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(head) > MAX_META:
            raise ValueError("session meta is too large")
        self.t_us = int(round(start * 1e6))
        self.messages = 0
        self.bytes = 0
        self.gaps = 0
        self.redacted = 0
        self.end = start
        self.closed = False
        self.tail = None
        self.f = None
        self.raw = None
        self.compression = "zstd" if zstd is not None else "gzip"
        self.buf = bytearray(MAGIC + struct.pack("<I", len(head)) + head)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, 0o600)
        try:
            self.raw = os.fdopen(fd, "wb")
        except BaseException:
            os.close(fd)
            self._unlink()
            raise
        try:
            if zstd is not None:
                self.f = zstd.ZstdFile(self.raw, "wb", level=3)
            else:
                self.f = gzip.GzipFile(filename="", mode="wb", compresslevel=6, fileobj=self.raw, mtime=0)
            self._spill()
        except BaseException:
            self._release()
            self._unlink()
            raise

    def _dt(self, t):
        now = int(round(t * 1e6))
        dt = now - self.t_us
        if dt < 0:
            dt = 0
        else:
            self.t_us = now
        if t > self.end:
            self.end = t
        return varint(dt)

    def message(self, t, side, mt, body, ok):
        n = len(body)
        flags = (side & 1) | (0 if ok else BAD)
        keep = True
        if side == C2S and (mt in REDACT_C2S or not (self.client_input or mt in KEEP_C2S)):
            flags |= REDACTED
            self.redacted += 1
            keep = False
        else:
            limit = BULK_LIMITS.get(mt)
            if limit is not None and n > limit:
                flags |= BULK
                keep = False
        buf = self.buf
        buf.append(1)
        buf += self._dt(t)
        buf += struct.pack("<BH", flags, mt & 0xFFFF)
        buf += varint(n)
        if keep and n:
            buf += body
            self.bytes += n
        self.messages += 1
        if len(buf) >= WRITE_BATCH:
            self._spill()

    def gap(self, t, side):
        buf = self.buf
        buf.append(2)
        buf += self._dt(t)
        buf.append(side & 1)
        self.gaps += 1
        if len(buf) >= WRITE_BATCH:
            self._spill()

    def _spill(self):
        if self.buf:
            data = self.buf
            self.buf = bytearray()
            self.f.write(data)

    def flush(self):
        if self.closed:
            return
        self._spill()
        if self.compression == "zstd":
            self.f.flush(zstd.ZstdFile.FLUSH_BLOCK)
        else:
            self.f.flush(zlib.Z_SYNC_FLUSH)
        self.raw.flush()
        os.fsync(self.raw.fileno())

    def close(self, extra=None):
        if self.closed:
            return self.tail
        tail = {"end": self.end, "messages": self.messages, "bytes": self.bytes, "gaps": self.gaps,
                "redacted": self.redacted}
        if extra:
            tail.update(extra)
        self.closed = True
        self.tail = tail
        try:
            data = json.dumps(tail, ensure_ascii=False, allow_nan=False, default=str).encode("utf-8")
            self.buf += b"\x03" + varint(len(data)) + data
            self._spill()
            self.f.close()
            self.raw.flush()
            os.fsync(self.raw.fileno())
            self.raw.close()
        except BaseException:
            self._release()
            raise
        return tail

    def abort(self, extra=None):
        try:
            return self.close(extra)
        except (OSError, ValueError):
            return self.tail

    def _release(self):
        for obj in (self.f, self.raw):
            if obj is not None:
                try:
                    obj.close()
                except (OSError, ValueError):
                    pass

    def _unlink(self):
        try:
            os.unlink(self.path)
        except OSError:
            pass


def _read_varint(f):
    n = 0
    shift = 0
    read = f.read
    while shift < 64:
        c = read(1)
        if not c:
            raise EOFError
        b = c[0]
        n |= (b & 0x7F) << shift
        if not b & 0x80:
            return n
        shift += 7
    raise ValueError("varint too long")


def _open_read(path):
    raw = open(path, "rb", buffering=0)
    try:
        head = raw.read(6)
        raw.seek(0)
        if head[:4] == ZSTD_MAGIC:
            if zstd is None:
                raise SessionError("zstd sessions need Python 3.14+ (compression.zstd)")
            inner = zstd.ZstdFile(raw, "rb")
        elif head[:2] == GZIP_MAGIC:
            inner = gzip.GzipFile(fileobj=raw, mode="rb")
        elif head == XZ_MAGIC:
            inner = lzma.LZMAFile(raw, "rb")
        else:
            inner = raw
        return io.BufferedReader(inner, READ_BUFFER), raw
    except BaseException:
        raw.close()
        raise


def _close_pair(reader, raw):
    for obj in (reader, raw):
        try:
            obj.close()
        except (OSError, ValueError):
            pass


def _read_head(reader):
    if reader.read(len(MAGIC)) != MAGIC:
        raise SessionError("not a byondcap session")
    size = reader.read(4)
    if len(size) != 4:
        raise SessionError("truncated session header")
    n = struct.unpack("<I", size)[0]
    if n > MAX_META:
        raise SessionError("session header is too large")
    blob = reader.read(n)
    if len(blob) != n:
        raise SessionError("truncated session header")
    try:
        meta = json.loads(blob.decode("utf-8"))
    except ValueError as e:
        raise SessionError("bad session header") from e
    if not isinstance(meta, dict):
        raise SessionError("bad session header")
    start = _start_of(meta)
    if start is None:
        raise SessionError("session header has no start time")
    meta["start"] = start
    return meta


def read_session(path):
    reader, raw = _open_read(path)
    try:
        meta = _read_head(reader)
    except SessionError:
        _close_pair(reader, raw)
        raise
    except _STREAM_ERRORS as e:
        _close_pair(reader, raw)
        raise SessionError("unreadable session: %s" % type(e).__name__) from e
    except BaseException:
        _close_pair(reader, raw)
        raise

    def records():
        t_us = int(round(meta["start"] * 1e6))
        read = reader.read
        try:
            while True:
                kind = read(1)
                if not kind:
                    meta["truncated"] = True
                    return
                k = kind[0]
                if k == 1:
                    t_us += _read_varint(reader)
                    head = read(3)
                    if len(head) != 3:
                        meta["truncated"] = True
                        return
                    flags = head[0]
                    mt = head[1] | (head[2] << 8)
                    n = _read_varint(reader)
                    if flags & DROPPED:
                        body = b""
                    else:
                        if n > MAX_LEN:
                            raise ValueError("oversized record")
                        body = read(n)
                        if len(body) != n:
                            meta["truncated"] = True
                            return
                    yield t_us / 1e6, flags & 1, mt, body, flags
                elif k == 2:
                    t_us += _read_varint(reader)
                    side = read(1)
                    if not side:
                        meta["truncated"] = True
                        return
                    yield t_us / 1e6, side[0] & 1, -1, b"", 0
                elif k == 3:
                    n = _read_varint(reader)
                    if n > MAX_META:
                        raise ValueError("oversized session tail")
                    data = read(n)
                    tail = json.loads(data.decode("utf-8"))
                    if isinstance(tail, dict):
                        tail.pop("start", None)
                        meta.update(tail)
                    return
                else:
                    raise ValueError("unknown record kind %d" % k)
        except _STREAM_ERRORS as e:
            meta["truncated"] = True
            meta["readError"] = type(e).__name__
            return
        finally:
            _close_pair(reader, raw)
    return meta, records()


def summarize(path):
    meta, records = read_session(path)
    first = last = None
    messages = gaps = size = redacted = 0
    for t, side, mt, body, flags in records:
        if first is None:
            first = t
        last = t
        if mt < 0:
            gaps += 1
            continue
        messages += 1
        size += len(body)
        if flags & REDACTED:
            redacted += 1
    end = meta.get("end")
    if not isinstance(end, (int, float)) or isinstance(end, bool):
        end = last if last is not None else meta["start"]
    return {"start": meta["start"], "end": float(end), "first": first, "last": last, "messages": messages,
            "gaps": gaps, "bytes": size, "redacted": redacted, "version": meta.get("version"),
            "build": meta.get("build"), "client": meta.get("client"), "server": meta.get("server"),
            "complete": not meta.get("truncated"), "error": meta.get("readError")}
