from __future__ import annotations

import json
import logging
import math
import os
import re
import secrets
import shutil
import stat
import time
import unicodedata
from typing import Any, Iterable, Iterator, NamedTuple

if os.name == "posix":
    import fcntl
else:
    import msvcrt

log = logging.getLogger(__name__)

IS_POSIX = os.name == "posix"
IS_WINDOWS = os.name == "nt"
MAX_IID = 2_147_483_647
CKEY_MAX = 64
JSON_MAX_BYTES = 64 << 20
ROUND_KEY_RE = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,94}[A-Za-z0-9_-])?\Z")
POV_ID_RE = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,94}[A-Za-z0-9_-])?\Z")
CKEY_RE = re.compile(r"\A[a-z0-9]{1,64}\Z")
_IID_TEXT_RE = re.compile(r"\A[1-9][0-9]{0,9}\Z")
_BINARY = getattr(os, "O_BINARY", 0)
_SURROGATES = re.compile("[\ud800-\udfff]")
_SPACES = frozenset("\t\n\r\x0b\x0c\x1c\x1d\x1e\x1f\x85  ")
_DROPPED_CATEGORIES = frozenset(("Cc", "Cf", "Cs", "Co"))


class DiskUsage(NamedTuple):
    total: int
    used: int
    free: int


class FileLock:
    def __init__(self, path: str, timeout: float = 10.0) -> None:
        self.path = path
        self.timeout = timeout
        self._fd: int | None = None

    def __enter__(self) -> FileLock:
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | _BINARY, 0o600)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                if IS_POSIX:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                else:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise TimeoutError(f"lock is busy: {self.path}") from None
                time.sleep(0.05)
        self._fd = fd
        return self

    def __exit__(self, *exc_info: object) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            if IS_POSIX:
                fcntl.flock(fd, fcntl.LOCK_UN)
            else:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        finally:
            os.close(fd)


def now() -> float:
    return time.time()


def utc_compact(ts: float | None = None) -> str:
    return time.strftime("%Y%m%d-%H%M%S", time.gmtime(time.time() if ts is None else ts))


def valid_round_key(key: object) -> bool:
    return isinstance(key, str) and ROUND_KEY_RE.match(key) is not None


def valid_pov_id(value: object) -> bool:
    return isinstance(value, str) and POV_ID_RE.match(value) is not None


def valid_iid(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value <= MAX_IID


def check_iid(value: object) -> int:
    if not valid_iid(value):
        raise ValueError("invalid instance id")
    return int(value)


def parse_iid(value: object) -> int | None:
    if valid_iid(value):
        return int(value)
    if isinstance(value, str) and _IID_TEXT_RE.match(value.strip()):
        number = int(value.strip())
        return number if number <= MAX_IID else None
    return None


def normalize_ckey(key: object) -> str:
    if not isinstance(key, str):
        return ""
    return "".join(ch for ch in key if ch.isascii() and ch.isalnum()).lower()[:CKEY_MAX]


def clean_text(value: object, limit: int = 256) -> str:
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, int):
        value = str(int(value))
    if not isinstance(value, str) or limit <= 0:
        return ""
    if len(value) > limit * 4 + 64:
        value = value[: limit * 4 + 64]
    out: list[str] = []
    for ch in value:
        if ch in _SPACES:
            out.append(" ")
        elif ch.isascii():
            if " " <= ch < "\x7f":
                out.append(ch)
        elif unicodedata.category(ch) not in _DROPPED_CATEGORIES:
            out.append(ch)
    return "".join(out).strip()[:limit].strip()


def _reject_constant(name: str) -> Any:
    raise ValueError("non-standard JSON constant")


def _parse_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("non-finite JSON number")
    return value


def _parse_int(text: str) -> int:
    if len(text) > 40:
        raise ValueError("JSON integer is too long")
    return int(text)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key in JSON object")
        out[key] = value
    return out


def _check_strings(value: Any) -> None:
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            if _SURROGATES.search(item):
                raise ValueError("invalid unicode in JSON string")
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)


def loads_strict(data: bytes | bytearray | memoryview | str) -> Any:
    text = data if isinstance(data, str) else bytes(data).decode("utf-8")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
            parse_float=_parse_float,
            parse_int=_parse_int,
        )
    except RecursionError:
        raise ValueError("JSON nesting is too deep") from None
    _check_strings(value)
    return value


def json_dumps(obj: Any, indent: int | None = None) -> str:
    if indent is None:
        return json.dumps(obj, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    return json.dumps(obj, ensure_ascii=False, allow_nan=False, indent=indent)


def json_bytes(obj: Any, indent: int | None = None) -> bytes:
    return json_dumps(obj, indent).encode("utf-8", "replace")


def file_stamp(path: str) -> tuple[int, int, int] | None:
    try:
        st = os.stat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    return (st.st_mtime_ns, st.st_size, st.st_ino)


def read_json(path: str, default: Any = None, strict: bool = False, max_bytes: int = JSON_MAX_BYTES) -> Any:
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes + 1)
    except (FileNotFoundError, NotADirectoryError):
        return default
    try:
        if len(data) > max_bytes:
            raise ValueError("file is too large")
        return loads_strict(data)
    except ValueError as exc:
        if strict:
            raise
        log.warning("ignoring unreadable JSON file %s: %s", path, exc)
        return default


def ensure_dir(path: str, mode: int = 0o700) -> str:
    target = os.path.abspath(path)
    missing: list[str] = []
    current = target
    while not os.path.isdir(current):
        missing.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    for directory in reversed(missing):
        try:
            os.mkdir(directory, mode)
        except FileExistsError:
            if not os.path.isdir(directory):
                raise
            continue
        if IS_POSIX:
            os.chmod(directory, mode)
    return target


def posix_private(path: str) -> None:
    if not IS_POSIX:
        return
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(st.st_mode):
        return
    mode = 0o700 if stat.S_ISDIR(st.st_mode) else 0o600
    if stat.S_IMODE(st.st_mode) != mode:
        os.chmod(path, mode)


def fsync_dir(path: str) -> None:
    if not IS_POSIX:
        return
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _replace(source: str, target: str) -> None:
    attempts = 10 if IS_WINDOWS else 1
    for attempt in range(attempts):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt + 1 >= attempts:
                raise
            time.sleep(0.05 * (attempt + 1))


def atomic_write_bytes(path: str, data: bytes, mode: int = 0o600) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    tmp = os.path.join(directory, "." + os.path.basename(path) + "." + secrets.token_hex(6) + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY, mode)
    try:
        try:
            if IS_POSIX:
                os.fchmod(fd, mode)
            _write_all(fd, bytes(data))
            os.fsync(fd)
        finally:
            os.close(fd)
        _replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    fsync_dir(directory)


def atomic_write_json(path: str, obj: Any, indent: int | None = None, mode: int = 0o600) -> None:
    atomic_write_bytes(path, json_bytes(obj, indent) + b"\n", mode)


def append_jsonl(path: str, row: Any, fsync: bool = False) -> None:
    line = json_bytes(row) + b"\n"
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT | _BINARY, 0o600)
    try:
        size = os.fstat(fd).st_size
        if size:
            os.lseek(fd, size - 1, os.SEEK_SET)
            if os.read(fd, 1) != b"\n":
                line = b"\n" + line
        _write_all(fd, line)
        if fsync:
            os.fsync(fd)
    finally:
        os.close(fd)


def iter_jsonl(path: str) -> Iterator[dict[str, Any]]:
    try:
        fh = open(path, "rb")
    except (FileNotFoundError, NotADirectoryError):
        return
    with fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            try:
                value = loads_strict(raw)
            except ValueError:
                continue
            if isinstance(value, dict):
                yield value


def read_jsonl(path: str) -> list[dict[str, Any]]:
    return list(iter_jsonl(path))


def _real(path: str) -> str:
    return os.path.normcase(os.path.realpath(path))


def is_within(path: str, roots: str | Iterable[str]) -> bool:
    if isinstance(roots, (str, os.PathLike)):
        roots = [roots]
    try:
        target = _real(os.fspath(path))
    except (OSError, ValueError, TypeError):
        return False
    for root in roots:
        try:
            base = _real(os.fspath(root))
        except (OSError, ValueError, TypeError):
            continue
        if target == base:
            return True
        prefix = base if base.endswith(os.sep) else base + os.sep
        if target.startswith(prefix):
            return True
    return False


def safe_join(root: str, *parts: str) -> str:
    for part in parts:
        if not isinstance(part, str) or not part or "\x00" in part:
            raise ValueError("invalid path component")
        if part.startswith(("/", "\\")) or os.path.isabs(part) or os.path.splitdrive(part)[0]:
            raise ValueError("absolute path component")
    real_root = os.path.realpath(root)
    candidate = os.path.realpath(os.path.join(real_root, *parts))
    if not is_within(candidate, [real_root]):
        raise ValueError("path escapes its root")
    return candidate


def remove_tree(path: str, root: str) -> bool:
    target = os.path.abspath(path)
    real_root = os.path.realpath(root)
    parent = os.path.realpath(os.path.dirname(target))
    if not is_within(parent, [real_root]) or _real(target) == os.path.normcase(real_root):
        raise ValueError("refusing to remove a path outside its root")
    try:
        st = os.lstat(target)
    except FileNotFoundError:
        return False
    if stat.S_ISDIR(st.st_mode):
        shutil.rmtree(target)
    else:
        os.unlink(target)
    return True


def disk_usage(path: str) -> DiskUsage | None:
    current = os.path.abspath(path)
    while True:
        try:
            usage = shutil.disk_usage(current)
            return DiskUsage(usage.total, usage.used, usage.free)
        except (FileNotFoundError, NotADirectoryError):
            parent = os.path.dirname(current)
            if parent == current:
                return None
            current = parent
        except OSError:
            return None


def dir_size(path: str) -> int:
    try:
        st = os.lstat(path)
    except OSError:
        return 0
    if not stat.S_ISDIR(st.st_mode):
        return st.st_size if stat.S_ISREG(st.st_mode) else 0
    total = 0
    pending = [path]
    while pending:
        current = pending.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    pending.append(entry.path)
                elif entry.is_file(follow_symlinks=False):
                    total += entry.stat(follow_symlinks=False).st_size
            except OSError:
                continue
    return total
