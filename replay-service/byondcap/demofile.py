import json
import struct

TURF = 0x01000000
OBJ = 0x02000000
MOB = 0x03000000
IMAGE = 0x0D000000
CHUNK_TIME = 0x00
CHUNK_SIZE = 0x01
CHUNK_TURF = 0x02
CHUNK_OBJ = 0x03
CHUNK_MOB = 0x04
CHUNK_CHAT = 0x08
CHUNK_CLIENT = 0x09
CHUNK_RESOURCE = 0x0A
CHAT_CLIENTS = 0x01
CHAT_WORLD = 0x02
CHAT_PLAIN = 0x10
DIR_INDEX = {0: 0, 1: 1, 2: 0, 4: 2, 8: 3, 5: 6, 6: 4, 9: 7, 10: 5}
NONE_APPEARANCE = 0xFFFF
MAX_REF = 0xFFFFFF
WRITE_BUFFER = 1 << 20


def vlq(n):
    out = [n & 0x7F]
    n >>= 7
    while n:
        out.append(0x80 | (n & 0x7F))
        n >>= 7
    return bytes(reversed(out))


def _id_bytes(flag, n):
    if n < 0x100:
        return bytes([flag | 2, n])
    if n < 0x10000:
        return bytes([flag | 4, n >> 8, n & 0xFF])
    return bytes([flag | 6, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF])


def resource_chunk(rid, blob):
    data = struct.pack("<I", rid) + bytes(blob)
    return bytes([CHUNK_RESOURCE]) + vlq(len(data)) + data


class DemoFile:
    def __init__(self, path, revdata):
        info = json.dumps(revdata, separators=(",", ":")).encode("utf-8")
        self.f = open(path, "wb", buffering=WRITE_BUFFER)
        self.f.write(bytes([0xCB, 0, 0]) + info + b"\x00")
        self.load_pos = self.f.tell()
        self.load_end = None
        self.f.write(struct.pack("<I", 0))
        self.strings = {}
        self.string_written = set()
        self.resource_written = set()
        self.resource_paths = {}
        self.resource_blobs = {}
        self.pending_blobs = []
        self.embedded = 0
        self.appearances = {}
        self.appearance_written = set()
        self.next_appearance = 1
        self.time = None
        self.chunks = 0
        self.closed = False

    def close(self):
        if self.closed:
            return
        self.flush_blobs()
        self.f.write(b"\x00")
        end = self.f.tell()
        self.f.seek(self.load_pos)
        self.f.write(struct.pack("<I", max(1, self.load_end or end)))
        self.closed = True
        self.f.close()

    def abort(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.f.close()
        except (OSError, ValueError):
            pass

    def chunk(self, kind, data):
        self.f.write(bytes([kind]) + vlq(len(data)) + data)
        self.chunks += 1

    def set_time(self, t):
        if self.time is not None and t <= self.time:
            return
        if self.load_end is None:
            self.load_end = self.f.tell()
        self.time = t
        self.chunk(CHUNK_TIME, struct.pack("<f", t))

    def resize(self, maxx, maxy, maxz):
        self.chunk(CHUNK_SIZE, struct.pack("<HHH", maxx, maxy, maxz))

    def string(self, text):
        if not text:
            return b"\x00"
        if "\x00" in text:
            text = text.replace("\x00", "")
            if not text:
                return b"\x00"
        sid = self.strings.get(text)
        if sid is None:
            sid = len(self.strings) + 1
            if sid > MAX_REF:
                raise ValueError("demo string table is full")
            self.strings[text] = sid
        if sid in self.string_written:
            return _id_bytes(0, sid)
        self.string_written.add(sid)
        return _id_bytes(1, sid) + text.encode("utf-8", "replace") + b"\x00"

    def resource(self, rid):
        if rid is None:
            return b"\x00"
        if rid in self.resource_written:
            return _id_bytes(0, rid)
        self.resource_written.add(rid)
        blob = self.resource_blobs.get(rid)
        if blob is not None:
            self.pending_blobs.append((rid, blob))
        path = self.resource_paths.get(rid)
        if path is None:
            return _id_bytes(0, rid)
        return _id_bytes(1, rid) + path.replace("\x00", "").encode("utf-8") + b"\x00"

    def flush_blobs(self):
        for rid, blob in self.pending_blobs:
            self.chunk(CHUNK_RESOURCE, struct.pack("<I", rid) + blob)
            self.embedded += 1
        self.pending_blobs = []

    def appearance_id(self, key):
        aid = self.appearances.get(key)
        if aid is None:
            aid = self.next_appearance
            if aid > MAX_REF:
                raise ValueError("demo appearance table is full")
            self.next_appearance += 1
            if self.next_appearance == NONE_APPEARANCE:
                self.next_appearance += 1
            self.appearances[key] = aid
        return aid

    def appearance(self, key, build):
        if key is None:
            return struct.pack("<I", NONE_APPEARANCE)
        aid = self.appearance_id(key)
        if aid in self.appearance_written:
            return struct.pack("<I", aid)
        self.appearance_written.add(aid)
        return struct.pack("<I", aid | 0x1000000) + self._define(build(key), build)

    def _define(self, a, build):
        daf = DIR_INDEX.get(a.get("dir", 2), 0)
        body = bytearray()
        if a.get("name"):
            daf |= 0x100
            body += self.string(a["name"])
        if a.get("screen_loc"):
            daf |= 0x400
            body += self.string(a["screen_loc"])
        body += self.resource(a.get("icon"))
        body += self.string(a.get("icon_state", ""))
        if a.get("maptext"):
            daf |= 0x800
            body += self.string(a["maptext"])
            body += struct.pack("<hhhh", a.get("maptext_x", 0), a.get("maptext_y", 0),
                                a.get("maptext_w", 32), a.get("maptext_h", 32))
        over = a.get("overlays") or []
        under = a.get("underlays") or []
        if over or under:
            daf |= 0x1000
            body += vlq(len(over))
            for k in over:
                body += self.appearance(k, build)
            body += vlq(len(under))
            for k in under:
                body += self.appearance(k, build)
        if a.get("invisibility"):
            daf |= 0x4000
            body.append(a["invisibility"] & 0xFF)
        px, py = a.get("pixel_x", 0), a.get("pixel_y", 0)
        if px or py:
            daf |= 0x10000
            body += struct.pack("<hh", px, py)
        pw, pz = a.get("pixel_w", 0), a.get("pixel_z", 0)
        if pw or pz:
            daf |= 0x20000
            body += struct.pack("<hh", pw, pz)
        layer = a.get("layer", 3.0)
        if layer != 3.0:
            daf |= 0x2000
            body += struct.pack("<f", layer)
        plane = a.get("plane", -32767)
        if plane != -32767:
            daf |= 0x40000
            body += struct.pack("<h", plane)
        tr = a.get("transform")
        if tr and tuple(tr) != (1.0, 0.0, 0.0, 0.0, 1.0, 0.0):
            daf |= 0x80000
            body += struct.pack("<6f", *tr)
        color = a.get("color", 0xFFFFFFFF)
        if color != 0xFFFFFFFF:
            daf |= 0x100000
            body += struct.pack("<I", color)
        cm = a.get("color_matrix")
        if cm:
            daf |= 0x200000
            body += bytes([0xF7]) + struct.pack("<20f", *cm)
        daf |= (a.get("blend", 0) & 7) << 24
        daf |= (a.get("mouse_opacity", 1) & 3) << 27
        head = struct.pack("<IH", daf, a.get("appearance_flags", 0) & 0xFFFF)
        return head + bytes(body)

    def atoms(self, kind, updates):
        self.flush_blobs()
        if not updates:
            return
        out = bytearray()
        cur = 0
        i = 0
        n = len(updates)
        while i < n:
            j = i
            while j + 1 < n and updates[j + 1][0] == updates[j][0] + 1:
                j += 1
            start = updates[i][0]
            out += vlq(start - cur)
            out += vlq(j - i + 1)
            for k in range(i, j + 1):
                out += updates[k][1]
            cur = updates[j][0] + 1
            i = j + 1
        out += b"\x00"
        self.chunk(kind, bytes(out))

    def update(self, appearance=None, loc=None, vis=None):
        flags = 0
        body = bytearray()
        if appearance is not None:
            flags |= 0x01
            body += appearance
        if loc is not None:
            flags |= 0x02
            body += struct.pack("<I", loc)
        if vis is not None:
            flags |= 0x04
            body += vlq(len(vis))
            for v in vis:
                body += struct.pack("<I", v)
        return bytes([flags]) + bytes(body)

    def client(self, cid, login=None, mob=None, logout=False, view=None, eye=None):
        flags = 0
        body = bytearray()
        if logout:
            flags |= 2
        if login is not None:
            flags |= 1
            body += self.string(login[0]) + self.string(login[1])
        if mob is not None:
            flags |= 4
            body += struct.pack("<I", mob)
        if view is not None:
            flags |= 8
            body += bytes([view[0] & 0xFF, view[1] & 0xFF])
        if eye is not None:
            flags |= 16
            body += struct.pack("<I", eye)
        self.chunk(CHUNK_CLIENT, struct.pack("<HB", cid, flags) + bytes(body))

    def chat(self, cids, message, plain=False, world=False):
        flags = 0
        body = bytearray()
        if cids:
            flags |= CHAT_CLIENTS
            body += vlq(len(cids))
            for c in cids:
                body += struct.pack("<H", c)
        if world:
            flags |= CHAT_WORLD
        if plain:
            flags |= CHAT_PLAIN
        self.chunk(CHUNK_CHAT, bytes([flags]) + bytes(body) + self.string(message))
