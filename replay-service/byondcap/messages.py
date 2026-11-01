import json
import struct
import urllib.parse

NONE16 = 0xFFFF
NONE32 = 0xFFFFFFFF


class Truncated(Exception):
    pass


class Reader:
    __slots__ = ("b", "o", "wide")

    def __init__(self, b, wide=True, o=0):
        self.b = b
        self.o = o
        self.wide = wide

    def left(self):
        return len(self.b) - self.o

    def _need(self, n):
        if self.o + n > len(self.b):
            raise Truncated(self.o)

    def u8(self):
        self._need(1)
        v = self.b[self.o]
        self.o += 1
        return v

    def u16(self):
        self._need(2)
        v = struct.unpack_from("<H", self.b, self.o)[0]
        self.o += 2
        return v

    def i16(self):
        self._need(2)
        v = struct.unpack_from("<h", self.b, self.o)[0]
        self.o += 2
        return v

    def u32(self):
        self._need(4)
        v = struct.unpack_from("<I", self.b, self.o)[0]
        self.o += 4
        return v

    def f32(self):
        self._need(4)
        v = struct.unpack_from("<f", self.b, self.o)[0]
        self.o += 4
        return v

    def rid(self):
        return self.u32() if self.wide else self.u16()

    def none(self):
        return NONE32 if self.wide else NONE16

    def cstr(self):
        e = self.b.find(b"\x00", self.o)
        if e < 0:
            raise Truncated(self.o)
        v = self.b[self.o:e].decode("utf-8", "replace")
        self.o = e + 1
        return v

    def skip(self, n):
        self._need(n)
        self.o += n


def reply(body):
    version, build = struct.unpack_from("<II", body, 0)
    return {"version": version, "build": build}


def view_resize(body):
    r = Reader(body)
    vals = []
    while r.left() >= 2:
        vals.append(r.u16())
    return vals


def rsc_preload(body):
    return [struct.unpack_from("<IB", body, i) for i in range(0, len(body) - 4, 5)]


def rsc_name(body, wide=True):
    r = Reader(body, wide)
    idx = r.u32()
    return idx, r.cstr()


def appearance(body, wide=True, version=0x204, verb_wide=False):
    r = Reader(body, wide)
    a = {"id": r.rid()}
    a["name"] = r.cstr()
    a["desc"] = r.cstr()
    a["icon"] = r.rid()
    a["icon_state"] = r.cstr()
    a["text"] = r.cstr()
    if version > 0x1ED:
        a["maptext"] = r.cstr()
        a["maptext_w"] = r.u16()
        a["maptext_h"] = r.u16()
        if version > 0x1FB:
            a["maptext_x"] = r.i16()
            a["maptext_y"] = r.i16()
    a["dir"] = r.u8()
    a["flags"] = r.u32() if version >= 0x132 else r.u8()
    refs = []
    if version >= 0x132:
        for _ in range(3):
            k = r.u8()
            refs.append(r.rid() if k == 2 else None)
    a["refs"] = refs
    a["base"] = r.rid()
    nv = r.u16()
    vr = r.u32 if verb_wide else r.u16
    a["verbs"] = [vr() for _ in range(nv)]
    a["overlays"] = []
    a["underlays"] = []
    if r.left() >= 2:
        a["overlays"] = [r.rid() for _ in range(r.u16())]
        if r.left() >= 2:
            a["underlays"] = [r.rid() for _ in range(r.u16())]
    if r.left() >= 4:
        a["layer"] = r.f32()
        if r.left():
            a["screen_loc"] = r.cstr()
            if r.left():
                _tail(r, a, version)
    a["left"] = r.left()
    return a


def _tail(r, a, version):
    t = r.u8()
    if t & 0x80:
        r.o -= 1
        t = r.u32()
    a["tail"] = t
    if t & 0x01:
        a["b37"] = r.u8()
    if t & 0x02:
        a["b39"] = r.u8()
    if t & 0x04:
        a["b38"] = r.u8()
    if t & 0x08:
        a["pixel_x"] = r.i16()
        a["pixel_y"] = r.i16()
        if version >= 0x1FF:
            a["pixel_w"] = r.i16()
        a["pixel_z"] = r.i16()
    if t & 0x10:
        a["glide"] = r.f32()
    if t & 0x20:
        a["transform"] = [r.f32() for _ in range(6)]
    if t & 0x40:
        a["color"] = r.u32()
    if t & 0x100:
        a["blend"] = r.u8()
    if t & 0x200:
        a["plane"] = r.i16()
    if t & 0x400:
        a["color_matrix"] = [r.f32() for _ in range(20)]
    if t & 0x800:
        a["partial"] = "filters"
        return
    if t & 0x1000:
        a["render_source"] = r.cstr()
        a["render_target"] = r.cstr()
    if t & 0x2000:
        a["appearance_flags"] = r.u16()
    if t & 0x4000:
        a["vis_flags"] = r.u32()
    if t & 0x8000:
        a["x8000"] = (r.u16(), r.u16())


def atom_appearance(body, wide=True):
    r = Reader(body, wide)
    return r.rid(), r.rid()


def client_ref(body, wide=True):
    return Reader(body, wide).rid()


def _sections(r, version):
    gen = version > 0x1BE
    s = {}

    def idg():
        i = r.rid()
        return i, (r.u16() if gen else 0)
    s["A"] = [idg() for _ in range(r.u8())]
    b = []
    for _ in range(r.u8()):
        i, g = idg()
        x = r.u16()
        y = r.u16()
        z = r.u16() if version > 0x1FF else None
        b.append((i, g, x, y, z))
    s["B"] = b
    c = []
    for _ in range(r.u8()):
        i, g = idg()
        c.append((i, g, r.rid()))
    s["C"] = c
    d = []
    for _ in range(r.u8()):
        i, g = idg()
        d.append((i, g, r.u8()))
    s["D"] = d
    e = []
    for _ in range(r.u8()):
        i, g = idg()
        e.append((i, g, r.rid()))
    s["E"] = e
    if r.left():
        f = []
        for _ in range(r.u8()):
            i, g = idg()
            px = r.i16()
            py = r.i16()
            pw = r.i16() if version > 0x1FE else 0
            pz = r.i16()
            f.append((i, g, px, py, pw, pz))
        s["F"] = f
    if r.left():
        s["G"] = []
        for _ in range(r.u8()):
            i, g = idg()
            s["G"].append((i, g, r.u16(), r.u16(), r.u16(), r.u16()))
    if r.left():
        s["H"] = []
        for _ in range(r.u8()):
            i, g = idg()
            a = r.u16()
            b2 = r.u16()
            gl = r.f32() if version > 0x1FE else None
            s["H"].append((i, g, a, b2, gl))
    if version > 0x1FF and r.left():
        vis = []
        for _ in range(r.u8()):
            i = r.rid()
            g = r.u16()
            items = []
            for _ in range(r.u16()):
                k = r.u8()
                items.append((k, r.rid()))
            vis.append((i, g, items))
        s["I"] = vis
    if version > 0x201 and r.left():
        gone = []
        for _ in range(r.u8()):
            i = r.rid()
            g = r.u16()
            v = r.u32()
            if v != NONE16:
                s["partial"] = "particles"
                s["J"] = gone
                r.o = len(r.b)
                return s
            gone.append((i, g))
        s["J"] = gone
    if r.left():
        s["end"] = r.u8()
    if r.left():
        s["extra"] = r.left()
    return s


def obj_updates(body, wide=True, version=0x204):
    r = Reader(body, wide)
    flags = r.u8()
    head = {"flags": flags}
    if flags & 2:
        head["a"] = r.u16()
    if flags & 4:
        head["b"] = r.u16()
    s = _sections(r, version)
    s["head"] = head
    return s


def _plausible(s):
    if s.get("extra"):
        return False
    for i, g, x, y, z in s["B"]:
        if x != NONE16 and (x > 4096 or y > 4096 or (z is not None and z > 255)):
            return False
    for i, g, dr in s["D"]:
        if dr > 10:
            return False
    return True


def _mob_sub(r, version, head):
    sub = r.u8()
    head["sub"] = sub
    if sub & 1:
        head["see_invisible"] = r.u8()
    if sub & 2:
        head["see_in_dark"] = r.u8()
    if sub & 4:
        head["sight"] = r.u32()
    if sub & 8:
        head["pixel"] = (r.i16(), r.i16(), r.i16() if version >= 0x1FF else 0, r.i16())
    if sub & 0x10:
        head["s10"] = (r.u16(), r.u16())
    if sub & 0x20:
        head["s20"] = (r.u16(), r.u16(), r.u16(), r.u16())
    if sub & 0x40:
        head["bounds"] = (r.u16(), r.u16(), r.u16(), r.u16())


def mob_updates(body, wide=True, version=0x204, build=1666):
    r = Reader(body, wide)
    flags = r.u8()
    head = {"flags": flags}
    if flags & 2:
        head["x"] = r.u16()
        head["x_to"] = r.u16()
    if flags & 4:
        head["y"] = r.u16()
        head["y_to"] = r.u16()
    if version >= 0x155 and flags & 6:
        same = r.u8()
        if same == 0:
            head["eye_kind"] = r.u8()
            head["eye"] = r.u32()
        head["eye_mode"] = r.u8()
        head["u474"] = r.u32()
        if version > 0x201:
            head["u454"] = r.f32()
        if version >= 0x1FD:
            head["glide"] = r.f32()
            if version > 0x202 or build > 0x609:
                head["bc4"] = r.f32()
        head["view_x"] = r.u16()
        head["view_y"] = r.u16()
    if flags & 8:
        r.skip(2)
    if flags & 0x10:
        r.skip(2)
    if flags & 0x20:
        head["perspective"] = r.u8()
    start = r.o
    if not flags & 0x40:
        if flags & 0x80:
            _mob_sub(r, version, head)
        s = _sections(r, version)
        s["head"] = head
        return s
    tried = []
    for ln in [9] + [n for n in range(0, 65) if n != 9]:
        if start + ln > len(body):
            break
        try:
            rr = Reader(body, wide, start + ln)
            h2 = dict(head)
            if flags & 0x80:
                _mob_sub(rr, version, h2)
            s = _sections(rr, version)
            if rr.left() == 0 and _plausible(s):
                h2["block40"] = body[start:start + ln].hex()
                s["head"] = h2
                return s
        except (Truncated, struct.error, IndexError):
            tried.append(ln)
            continue
    raise Truncated(start)


class Grid:
    def __init__(self):
        self.maxx = 0
        self.maxy = 0
        self.w = 0
        self.h = 0
        self.x0 = None
        self.y0 = None
        self.z = None
        self.last = (True, 0, 0)
        self.fresh = False

    def resize(self, vals, dims=None):
        if len(vals) >= 4:
            self.maxx, self.maxy = vals[0], vals[1]
            self.w, self.h = dims if dims else (vals[2], vals[3])

    def _walk(self, r, full, ox0, oy0):
        mark = r.none() - (0 if r.wide else 1)
        cells = []
        run = 0
        prev = NONE16
        cur = NONE16
        w, h = self.w, self.h
        for y in range(h):
            for x in range(w):
                if not full and ox0 <= x <= ox0 + w - 1 and oy0 <= y <= oy0 + h - 1:
                    continue
                wx = self.x0 + x
                wy = self.y0 + y
                if wx < 0 or wy < 0 or wx >= self.maxx or wy >= self.maxy:
                    continue
                if run == 0:
                    v = r.rid()
                    if v == mark:
                        cur = prev
                        run = r.u8()
                    else:
                        cur = v
                        prev = v
                else:
                    run -= 1
                cells.append((wx, wy, cur))
        return cells

    def turfs(self, mt, body, wide=True):
        r = Reader(body, wide)
        x0 = r.i16()
        y0 = r.i16()
        z = r.u16()
        full = mt in (18, 97) or self.z is None or z != self.z
        ox0 = (self.x0 - x0) if self.x0 is not None else 0
        oy0 = (self.y0 - y0) if self.y0 is not None else 0
        self.x0, self.y0, self.z = x0, y0, z
        self.last = (full, ox0, oy0)
        self.fresh = True
        cells = self._walk(r, full, ox0, oy0)
        return {"x0": x0, "y0": y0, "z": z, "cells": cells, "left": r.left()}

    def areas(self, body, wide=True):
        r = Reader(body, wide)
        cells = []
        if self.fresh and self.x0 is not None:
            self.fresh = False
            full, ox0, oy0 = self.last
            cells = self._walk(r, full, ox0, oy0)
        pairs = []
        if r.left() >= 2:
            for _ in range(r.u16()):
                pairs.append((r.rid(), r.rid()))
        return {"cells": cells, "pairs": pairs, "left": r.left()}


def _strings(body):
    parts = body.split(b"\x00")
    return [p.decode("utf-8", "replace") for p in parts]


def _chat_json(text):
    try:
        data = json.loads(urllib.parse.unquote(text))
    except (ValueError, TypeError, RecursionError):
        return None
    found = []
    stack = [data]
    while stack:
        v = stack.pop()
        if isinstance(v, dict):
            for k in ("html", "text"):
                if isinstance(v.get(k), str):
                    found.append((k, v[k]))
            stack.extend(x for x in reversed(list(v.values())) if isinstance(x, (dict, list)))
        elif isinstance(v, list):
            stack.extend(x for x in reversed(v) if isinstance(x, (dict, list)))
    return found


def output(body):
    parts = _strings(body)
    text = parts[0] if parts else ""
    control = parts[1] if len(parts) > 1 else ""
    if control.startswith("statbrowser") or control.startswith("statpanel"):
        return None
    if text.startswith("%7b") or text.startswith("%7B") or text.startswith("{"):
        found = _chat_json(text)
        if not found:
            return None
        return [(k == "text", v) for k, v in found]
    if not text or control.startswith("tgui") or ":" in control and not control.startswith("browseroutput"):
        return None
    return [(False, text)]


def text_output(body):
    parts = _strings(body)
    text = parts[0] if parts else ""
    return [(False, text)] if text else None
