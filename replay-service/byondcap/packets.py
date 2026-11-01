import collections
import ipaddress
import logging
import os
import struct
import time

from .link import C2S, M32, S2C, Link, SessionWriter

FIN = 0x01
SYN = 0x02
RST = 0x04
ACK = 0x10
MAX_RECORD = 1 << 20
MAX_BLOCK = 16 << 20
HANDSHAKE = 0
RECORDING = 1
GONE = 2
EARLY_MESSAGES = 32
EARLY_BYTES = 1 << 16
DUP_WINDOW = 2.0

LOGGER = logging.getLogger(__name__)


class PcapError(ValueError):
    pass


def _read_exact(f, n):
    data = f.read(n)
    while data is not None and len(data) < n:
        more = f.read(n - len(data))
        if not more:
            break
        data += more
    return data or b""


def _pcap(f, head):
    if head in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
        nano = head[0] == 0x4D
    elif head in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = ">"
        nano = head[3] == 0x4D
    else:
        raise PcapError("not a pcap/pcapng stream")
    rest = _read_exact(f, 20)
    if len(rest) < 20:
        return
    snap, linktype = struct.unpack(e + "II", rest[12:20])
    linktype &= 0x0FFFFFFF
    limit = snap if 0 < snap <= MAX_RECORD else MAX_RECORD
    div = 1e9 if nano else 1e6
    while True:
        h = _read_exact(f, 16)
        if len(h) < 16:
            return
        sec, frac, incl, _ = struct.unpack(e + "IIII", h)
        if incl > limit or frac >= div:
            raise PcapError("pcap record framing lost")
        data = _read_exact(f, incl)
        if len(data) < incl:
            return
        yield sec + frac / div, linktype, data


def _pcapng(f):
    e = "<"
    ifaces = []
    first = True
    while True:
        if first:
            btype = 0x0A0D0D0A
            first = False
        else:
            raw = _read_exact(f, 4)
            if len(raw) < 4:
                return
            btype = struct.unpack(e + "I", raw)[0]
        if btype == 0x0A0D0D0A:
            raw_len = _read_exact(f, 4)
            bom = _read_exact(f, 4)
            if len(raw_len) < 4 or len(bom) < 4:
                return
            if bom == b"\x4d\x3c\x2b\x1a":
                e = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                e = ">"
            else:
                raise PcapError("bad pcapng byte-order magic")
            blen = struct.unpack(e + "I", raw_len)[0]
            if blen < 28 or blen > MAX_BLOCK or blen % 4:
                raise PcapError("bad pcapng section header")
            if len(_read_exact(f, blen - 12)) < blen - 12:
                return
            ifaces = []
            continue
        raw_len = _read_exact(f, 4)
        if len(raw_len) < 4:
            return
        blen = struct.unpack(e + "I", raw_len)[0]
        if blen < 12 or blen > MAX_BLOCK or blen % 4:
            raise PcapError("pcapng block framing lost")
        body = _read_exact(f, blen - 12)
        trailer = _read_exact(f, 4)
        if len(body) < blen - 12 or len(trailer) < 4:
            return
        if trailer != raw_len:
            raise PcapError("pcapng block framing lost")
        if btype == 1:
            if len(body) < 8:
                continue
            linktype = struct.unpack_from(e + "H", body, 0)[0]
            res = 1e-6
            o = 8
            while o + 4 <= len(body):
                code, ln = struct.unpack_from(e + "HH", body, o)
                if code == 0:
                    break
                if code == 9 and ln >= 1 and o + 4 < len(body):
                    v = body[o + 4]
                    res = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                o += 4 + ((ln + 3) & ~3)
            ifaces.append((linktype, res))
        elif btype == 6 and len(body) >= 20:
            iface, hi, lo, cap, _ = struct.unpack_from(e + "IIIII", body, 0)
            if iface < len(ifaces):
                lt, res = ifaces[iface]
                yield ((hi << 32) | lo) * res, lt, body[20:20 + cap]
        elif btype == 3 and ifaces and len(body) >= 4:
            lt, _ = ifaces[0]
            yield time.time(), lt, body[4:]
        elif btype == 2 and len(body) >= 20:
            iface, _, hi, lo, cap, _ = struct.unpack_from(e + "HHIIII", body, 0)
            if iface < len(ifaces):
                lt, res = ifaces[iface]
                yield ((hi << 32) | lo) * res, lt, body[20:20 + cap]


def read_packets(f):
    head = _read_exact(f, 4)
    if len(head) < 4:
        return
    if head == b"\x0a\x0d\x0d\x0a":
        yield from _pcapng(f)
    else:
        yield from _pcap(f, head)


def _ip_offset(linktype, data):
    if linktype == 1:
        if len(data) < 14:
            return None
        et = struct.unpack_from(">H", data, 12)[0]
        o = 14
        while et in (0x8100, 0x88A8) and len(data) >= o + 4:
            et = struct.unpack_from(">H", data, o + 2)[0]
            o += 4
        return o if et in (0x0800, 0x86DD) else None
    if linktype == 113:
        return 16
    if linktype == 276:
        return 20
    if linktype in (0, 108):
        return 4
    if linktype in (101, 12, 14, 228, 229):
        return 0
    return None


def parse_tcp(linktype, data):
    o = _ip_offset(linktype, data)
    if o is None or len(data) < o + 20:
        return None
    ver = data[o] >> 4
    if ver == 4:
        ihl = (data[o] & 0x0F) * 4
        if ihl < 20 or data[o + 9] != 6:
            return None
        total = struct.unpack_from(">H", data, o + 2)[0]
        if struct.unpack_from(">H", data, o + 6)[0] & 0x3FFF:
            return None
        src = bytes(data[o + 12:o + 16])
        dst = bytes(data[o + 16:o + 20])
        tcp = data[o + ihl:o + total] if total else data[o + ihl:]
    elif ver == 6:
        if len(data) < o + 40:
            return None
        nh = data[o + 6]
        plen = struct.unpack_from(">H", data, o + 4)[0]
        src = bytes(data[o + 8:o + 24])
        dst = bytes(data[o + 24:o + 40])
        p = o + 40
        end = o + 40 + plen
        while nh in (0, 43, 60) and p + 2 <= len(data):
            nh = data[p]
            p += (data[p + 1] + 1) * 8
        if nh != 6:
            return None
        tcp = data[p:end]
    else:
        return None
    if len(tcp) < 20:
        return None
    sport, dport, seq, _, off = struct.unpack_from(">HHIIH", tcp, 0)
    doff = (off >> 12) * 4
    if doff < 20:
        return None
    return src, dst, sport, dport, seq, off & 0x3F, bytes(tcp[doff:])


def _diff(a, b):
    return ((a - b + 0x80000000) & M32) - 0x80000000


class Stream:
    __slots__ = ("next", "pend", "pend_bytes", "waiting")

    def __init__(self, isn):
        self.next = (isn + 1) & M32
        self.pend = {}
        self.pend_bytes = 0
        self.waiting = None

    def push(self, seq, data, now=0.0, patience=3.0):
        out = []
        d = _diff(seq, self.next)
        if d <= 0:
            if -d < len(data):
                piece = data[-d:]
                out.append(piece)
                self.next = (self.next + len(piece)) & M32
                self._drain(out)
        else:
            cur = self.pend.get(seq)
            if cur is None or len(data) > len(cur):
                self.pend_bytes += len(data) - (len(cur) if cur else 0)
                self.pend[seq] = data
            if self.waiting is None:
                self.waiting = now
            if len(self.pend) > 4096 or self.pend_bytes > 16 << 20 or now - self.waiting > patience:
                self.skip(out)
        if not self.pend:
            self.waiting = None
        return out

    def _drain(self, out):
        while self.pend:
            best = None
            for seq in self.pend:
                if _diff(seq, self.next) <= 0:
                    best = seq
                    break
            if best is None:
                return
            data = self.pend.pop(best)
            self.pend_bytes -= len(data)
            d = _diff(best, self.next)
            if -d < len(data):
                piece = data[-d:]
                out.append(piece)
                self.next = (self.next + len(piece)) & M32

    def skip(self, out):
        while self.pend:
            seq = min(self.pend, key=lambda s: _diff(s, self.next))
            out.append(None)
            self.next = seq
            self._drain(out)
        self.waiting = None


def _addr(ip, port):
    return ("[%s]:%d" if ip.version == 6 else "%s:%d") % (ip, port)


def _reason(exc):
    if isinstance(exc, OSError) and exc.strerror:
        return "%s: %s" % (type(exc).__name__, exc.strerror)
    return type(exc).__name__


def _port(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value < 65536:
        raise ValueError("bad port %r" % (value,))
    return value


class Conn:
    __slots__ = ("key", "number", "isn", "link", "streams", "writer", "path", "state", "started", "opened", "last",
                 "closing", "client", "server", "client_ip", "client_port", "server_ip", "server_port", "early")

    def __init__(self, key, ts, number, isn):
        cip = ipaddress.ip_address(key[0])
        sip = ipaddress.ip_address(key[2])
        self.key = key
        self.number = number
        self.isn = isn
        self.link = Link()
        self.streams = [None, None]
        self.writer = None
        self.path = None
        self.state = HANDSHAKE
        self.started = ts
        self.opened = None
        self.last = ts
        self.closing = 0
        self.client_ip = str(cip)
        self.client_port = key[1]
        self.server_ip = str(sip)
        self.server_port = key[3]
        self.client = _addr(cip, key[1])
        self.server = _addr(sip, key[3])
        self.early = []

    @property
    def version(self):
        return self.link.version

    @property
    def build(self):
        return self.link.build

    @property
    def recording(self):
        return self.state == RECORDING


class Capture:
    def __init__(self, ports, session_path, session_meta=None, on_closed=None, idle=600.0, client_input=False,
                 handshake=30.0, patience=3.0, max_conns=4096, logger=None):
        self.ports = frozenset(_port(p) for p in ports)
        if not self.ports:
            raise ValueError("no game ports")
        if not callable(session_path):
            raise TypeError("session_path must be callable")
        self.session_path = session_path
        self.session_meta = session_meta
        self.on_closed = on_closed
        self.idle = float(idle)
        self.handshake = float(handshake)
        self.patience = float(patience)
        self.max_conns = max(1, int(max_conns))
        self.client_input = bool(client_input)
        self.logger = logger or LOGGER
        self.conns = {}
        self.pending = collections.OrderedDict()
        self.aliases = {}
        self.packets = 0
        self.connections = 0
        self.opened = 0
        self.closed = 0
        self.skipped = 0
        self.refused = 0
        self.duplicates = 0
        self.errors = 0
        self.bytes_closed = 0

    def packet(self, ts, linktype, data):
        p = parse_tcp(linktype, data)
        if p is None:
            return
        src, dst, sport, dport, seq, flags, payload = p
        if dport in self.ports:
            side = C2S
            key = (src, sport, dst, dport)
        elif sport in self.ports:
            side = S2C
            key = (dst, dport, src, sport)
        else:
            return
        self.packets += 1
        conn = self.conns.get(key)
        if flags & SYN:
            if side == C2S and not flags & ACK:
                if conn is not None:
                    if conn.isn == seq:
                        conn.last = ts
                        return
                    self._close(conn, "reconnect")
                conn = self._new(key, ts, seq)
                if conn is None:
                    return
            if conn is not None and conn.streams[side] is None:
                conn.streams[side] = Stream(seq)
                conn.last = ts
            return
        if conn is None:
            return
        conn.last = ts
        st = conn.streams[side]
        if st is not None and payload:
            self._deliver(conn, ts, side, st.push(seq, payload, ts, self.patience))
            if conn.state == GONE:
                return
            if conn.state == HANDSHAKE and st.pend_bytes + conn.link.buffered() > EARLY_BYTES:
                self._skip(conn)
                return
        if flags & RST:
            self._close(conn, "reset")
        elif flags & FIN:
            conn.closing |= 1 << side
            if conn.closing == 3:
                self._close(conn, "fin")

    def _new(self, key, ts, isn):
        alias = (key[0], key[1], key[3])
        other = self.aliases.get(alias)
        if other is not None and other.state != GONE and other.key != key and abs(ts - other.started) <= DUP_WINDOW:
            self.duplicates += 1
            return None
        if len(self.conns) >= self.max_conns and not self._evict():
            self.refused += 1
            return None
        self.connections += 1
        conn = Conn(key, ts, self.connections, isn)
        self.conns[key] = conn
        self.pending[key] = conn
        self.aliases[alias] = conn
        return conn

    def _evict(self):
        while self.pending:
            _, conn = self.pending.popitem(last=False)
            if conn.state == HANDSHAKE:
                self._skip(conn)
                return True
        return False

    def _deliver(self, conn, ts, side, chunks):
        link = conn.link
        for chunk in chunks:
            if chunk is None:
                link.gap(side)
                if conn.writer is not None:
                    try:
                        conn.writer.gap(ts, side)
                    except OSError as e:
                        self._finish(conn, "error", e)
                        return
                continue
            for side_m, mt, plain, ok in link.feed(side, chunk):
                self._emit(conn, ts, side_m, mt, plain, ok)
                if conn.state == GONE:
                    return
            if conn.state == HANDSHAKE and link.failed:
                self._skip(conn)
                return

    def _emit(self, conn, ts, side, mt, plain, ok):
        if conn.state == RECORDING:
            try:
                conn.writer.message(ts, side, mt, plain, ok)
            except OSError as e:
                self._finish(conn, "error", e)
            return
        link = conn.link
        if not link.ready():
            if side == C2S and link.key0 is None:
                self._skip(conn)
                return
            conn.early.append((ts, side, mt, plain, ok))
            if len(conn.early) > EARLY_MESSAGES or sum(len(m[3]) for m in conn.early) > EARLY_BYTES:
                self._skip(conn)
            return
        if not self._open(conn, ts):
            return
        w = conn.writer
        try:
            for m in conn.early:
                w.message(*m)
            conn.early = None
            w.message(ts, side, mt, plain, ok)
        except OSError as e:
            self._finish(conn, "error", e)

    def _open(self, conn, ts):
        conn.opened = conn.early[0][0] if conn.early else ts
        try:
            path = self.session_path(conn)
        except Exception:
            self.logger.exception("session_path hook failed")
            path = None
        if not path:
            self._skip(conn)
            return False
        meta = {}
        if self.session_meta is not None:
            try:
                extra = self.session_meta(conn)
                if extra:
                    meta.update(extra)
            except Exception:
                self.logger.exception("session_meta hook failed")
                self._skip(conn)
                return False
        link = conn.link
        meta.setdefault("client", conn.client)
        meta.setdefault("server", conn.server)
        meta.setdefault("source", "pcap")
        meta.setdefault("startedAt", conn.opened)
        meta["start"] = conn.opened
        meta["version"] = link.version
        meta["build"] = link.build
        meta["clientVersion"] = link.client_version
        meta["clientBuild"] = link.client_build
        meta["clientInput"] = self.client_input
        try:
            writer = SessionWriter(path, meta, client_input=self.client_input)
        except (OSError, ValueError, TypeError) as e:
            self.errors += 1
            self.logger.warning("cannot open session file %s: %s", os.path.basename(os.fspath(path)), _reason(e))
            self._skip(conn)
            return False
        conn.writer = writer
        conn.path = writer.path
        conn.state = RECORDING
        if self.pending.get(conn.key) is conn:
            del self.pending[conn.key]
        self.opened += 1
        self.logger.debug("session %d opened as %s", conn.number, os.path.basename(writer.path))
        return True

    def _drop(self, conn):
        conn.state = GONE
        key = conn.key
        if self.conns.get(key) is conn:
            del self.conns[key]
        if self.pending.get(key) is conn:
            del self.pending[key]
        alias = (key[0], key[1], key[3])
        if self.aliases.get(alias) is conn:
            del self.aliases[alias]
        conn.early = None
        conn.streams = [None, None]

    def _skip(self, conn):
        if conn.state == GONE:
            return
        self.skipped += 1
        self._drop(conn)

    def _flush_pending(self, conn):
        for side in (C2S, S2C):
            st = conn.streams[side]
            if st is not None and st.pend:
                out = []
                st.skip(out)
                self._deliver(conn, conn.last, side, out)
                if conn.state == GONE:
                    return

    def _close(self, conn, reason):
        if conn.state == GONE:
            return None
        if conn.state == RECORDING:
            self._flush_pending(conn)
        return self._finish(conn, reason)

    def _finish(self, conn, reason, error=None):
        if conn.state == GONE:
            return None
        self._drop(conn)
        w = conn.writer
        conn.writer = None
        if w is None:
            return None
        link = conn.link
        extra = {"version": link.version, "build": link.build, "bad": link.bad, "resyncs": link.resyncs,
                 "reason": reason}
        tail = None
        if error is None:
            try:
                tail = w.close(extra)
            except (OSError, ValueError) as e:
                error = e
        if error is not None:
            self.errors += 1
            extra["error"] = _reason(error)
            tail = w.abort(extra) or w.tail or extra
            self.logger.warning("session file %s closed after a write error: %s", os.path.basename(w.path),
                                extra["error"])
        row = {"file": os.path.basename(w.path), "client": conn.client, "server": conn.server,
               "start": w.meta["start"], "end": tail.get("end", w.end), "bytes": w.bytes,
               "messages": w.messages, "gaps": w.gaps, "version": link.version, "build": link.build,
               "reason": reason, "bad": link.bad, "resyncs": link.resyncs, "redacted": w.redacted}
        if error is not None:
            row["error"] = extra["error"]
        self.closed += 1
        self.bytes_closed += w.bytes
        self.logger.debug("session %d closed (%s): %d messages", conn.number, reason, w.messages)
        if self.on_closed is not None:
            try:
                self.on_closed(row)
            except Exception:
                self.logger.exception("on_closed hook failed")
        return row

    def flush_all(self):
        flushed = 0
        for conn in list(self.conns.values()):
            if conn.state != RECORDING or conn.writer is None:
                continue
            try:
                conn.writer.flush()
                flushed += 1
            except (OSError, ValueError) as e:
                self._finish(conn, "error", e)
        return flushed

    def close_all(self, reason):
        rows = 0
        for conn in list(self.conns.values()):
            if self._close(conn, reason) is not None:
                rows += 1
        self.conns.clear()
        self.pending.clear()
        self.aliases.clear()
        return rows

    def sweep(self, now):
        closed = 0
        for conn in list(self.conns.values()):
            if conn.state == GONE:
                continue
            if conn.state == HANDSHAKE:
                if now - conn.started > self.handshake or now - conn.last > self.idle:
                    self._skip(conn)
                continue
            if now - conn.last > self.idle:
                if self._close(conn, "idle") is not None:
                    closed += 1
                continue
            for side in (C2S, S2C):
                st = conn.streams[side]
                if st is not None and st.pend and st.waiting is not None and now - st.waiting > self.patience:
                    out = []
                    st.skip(out)
                    self._deliver(conn, conn.last, side, out)
                    if conn.state == GONE:
                        break
        return closed

    def sessions(self):
        out = []
        for conn in self.conns.values():
            w = conn.writer
            if conn.state == RECORDING and w is not None:
                out.append({"file": os.path.basename(w.path), "client": conn.client, "server": conn.server,
                            "start": w.meta["start"], "end": w.end, "bytes": w.bytes, "messages": w.messages,
                            "gaps": w.gaps})
        return out

    def stats(self):
        open_sessions = 0
        open_bytes = 0
        for conn in self.conns.values():
            if conn.state == RECORDING and conn.writer is not None:
                open_sessions += 1
                open_bytes += conn.writer.bytes
        return {"connections": len(self.conns), "openSessions": open_sessions, "sessions": self.closed,
                "opened": self.opened, "bytes": self.bytes_closed + open_bytes, "packets": self.packets,
                "skipped": self.skipped, "refused": self.refused, "duplicates": self.duplicates,
                "errors": self.errors}
