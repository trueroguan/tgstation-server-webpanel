from __future__ import annotations

import dataclasses
import enum
import ipaddress
import logging
import os
import re
import threading
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlsplit

from .fsutil import (
    atomic_write_json,
    check_iid,
    ensure_dir,
    file_stamp,
    is_within,
    loads_strict,
    parse_iid,
    read_json,
    valid_round_key,
)

log = logging.getLogger(__name__)

MIB = 1 << 20
GIB = 1 << 30
TIB = 1 << 40
CONFIG_MAX_BYTES = 1 << 20
CAPTURE_TOOLS = ("tcpdump", "dumpcap")

_PUBLIC_PATH_RE = re.compile(r"\A/[A-Za-z0-9/_-]*/\Z")
_REPO_RE = re.compile(r"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_IFACE_RE = re.compile(r"\A[A-Za-z0-9_.:-]{1,64}\Z")
_IFACE_DUMPCAP_RE = re.compile(r"\A[A-Za-z0-9_.:\\{}-]{1,64}\Z")
_API_VERSION_RE = re.compile(r"\A[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}\Z")
_ORIGIN_RE = re.compile(r"\Ahttps?://(?:[a-z0-9.-]+|\[[0-9a-f:.]+\])(?::[0-9]{1,5})?\Z")
_RSC_NAME_RE = re.compile(r"\A[A-Za-z0-9_][A-Za-z0-9_.+ -]{0,127}\Z")
_HOST_KEYS = (
    "listen", "gameListen", "publicPath", "dataDir", "allowedRoots", "viewerDir",
    "corsOrigins", "trustedProxies", "tgs", "processing", "instances",
)
_TGS_KEYS = ("url", "apiVersion", "timeoutSeconds", "verifyTls", "cacheSeconds", "instancePermissionSetWriteBit")
_PROCESSING_KEYS = ("workers", "niceness", "povCacheMiB")
_INSTANCE_KEYS = (
    "gamePorts", "interface", "captureTool", "capturePath", "captureBufferMiB",
    "captureKernelBufferMiB", "captureNiceness", "gameDir", "rscFiles", "repo",
)
_MISSING: Any = object()


def _join(path: str, key: object) -> str:
    return f"{path}.{key}" if path else str(key)


class ConfigError(ValueError):
    def __init__(self, errors: Iterable[tuple[str, str]] | str, field: str = "") -> None:
        items = [(field, errors)] if isinstance(errors, str) else list(errors)
        self.errors: list[tuple[str, str]] = [(str(path), str(message)) for path, message in items]
        text = "; ".join(f"{path}: {message}" if path else message for path, message in self.errors)
        super().__init__(text or "invalid configuration")

    @property
    def fields(self) -> list[dict[str, str]]:
        return [{"field": path, "message": message} for path, message in self.errors]


class _Check:
    def __init__(self) -> None:
        self.errors: list[tuple[str, str]] = []

    def fail(self, path: str, message: str) -> None:
        self.errors.append((path, message))

    def done(self) -> None:
        if self.errors:
            raise ConfigError(self.errors)

    def section(self, value: Any, path: str, keys: Iterable[str], required: bool = False) -> dict[str, Any]:
        if value is _MISSING:
            if required:
                self.fail(path, "is required")
            return {}
        if not isinstance(value, dict):
            self.fail(path, "must be an object")
            return {}
        allowed = set(keys)
        for key in value:
            if key not in allowed:
                self.fail(_join(path, key), "unknown field")
        return value

    def field(self, obj: dict[str, Any], key: str, path: str, default: Any = _MISSING) -> Any:
        if key in obj:
            return obj[key]
        if default is _MISSING:
            self.fail(_join(path, key), "is required")
        return default

    def integer(self, value: Any, path: str, lo: int, hi: int) -> int | None:
        if value is _MISSING:
            return None
        if isinstance(value, float) and value.is_integer():
            value = int(value)
        if isinstance(value, bool) or not isinstance(value, int):
            self.fail(path, "must be an integer")
            return None
        if value < lo or value > hi:
            self.fail(path, f"must be between {lo} and {hi}")
            return None
        return int(value)

    def number(self, value: Any, path: str, lo: float, hi: float) -> float | None:
        if value is _MISSING:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value:
            self.fail(path, "must be a number")
            return None
        if value < lo or value > hi:
            self.fail(path, f"must be between {lo:g} and {hi:g}")
            return None
        return float(value)

    def boolean(self, value: Any, path: str) -> bool | None:
        if value is _MISSING:
            return None
        if not isinstance(value, bool):
            self.fail(path, "must be true or false")
            return None
        return value

    def text(
        self,
        value: Any,
        path: str,
        pattern: re.Pattern[str] | None = None,
        max_len: int = 256,
        message: str = "has an invalid format",
    ) -> str | None:
        if value is _MISSING:
            return None
        if not isinstance(value, str):
            self.fail(path, "must be a string")
            return None
        if len(value) > max_len or any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            self.fail(path, f"must be at most {max_len} printable characters")
            return None
        if pattern is not None and not pattern.match(value):
            self.fail(path, message)
            return None
        return value

    def abspath(self, value: Any, path: str, allow_root: bool = True) -> str | None:
        text = self.text(value, path, None, 1024)
        if text is None:
            return None
        if not text or not os.path.isabs(text):
            self.fail(path, "must be an absolute path")
            return None
        norm = os.path.normpath(text)
        if not allow_root and os.path.dirname(norm) == norm:
            self.fail(path, "must not be a filesystem root")
            return None
        return norm

    def array(self, value: Any, path: str, lo: int, hi: int) -> list[Any] | None:
        if value is _MISSING:
            return None
        if not isinstance(value, list):
            self.fail(path, "must be an array")
            return None
        if len(value) < lo or len(value) > hi:
            self.fail(path, f"must have between {lo} and {hi} entries")
            return None
        return value

    def choice(self, value: Any, path: str, options: Iterable[str]) -> str | None:
        if value is _MISSING:
            return None
        allowed = tuple(options)
        if not isinstance(value, str) or value not in allowed:
            self.fail(path, "must be one of " + ", ".join(allowed))
            return None
        return value

    def enum(self, value: Any, path: str, kind: type[enum.IntEnum]) -> Any:
        number = self.integer(value, path, int(min(kind)), int(max(kind)))
        if number is None:
            return None
        try:
            return kind(number)
        except ValueError:
            self.fail(path, "is not a valid option")
            return None

    def ip(self, value: Any, path: str) -> str | None:
        text = self.text(value, path, None, 64)
        if text is None:
            return None
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            self.fail(path, "must be an IP address literal")
            return None

    def network(self, value: Any, path: str) -> str | None:
        text = self.text(value, path, None, 64)
        if text is None:
            return None
        try:
            return str(ipaddress.ip_network(text, strict=False))
        except ValueError:
            self.fail(path, "must be an IP address or network")
            return None

    def url(self, value: Any, path: str) -> str | None:
        text = self.text(value, path, None, 512)
        if text is None:
            return None
        try:
            parts = urlsplit(text)
            port_ok = parts.port is None or 0 < parts.port < 65536
        except ValueError:
            self.fail(path, "must be a valid URL")
            return None
        if parts.scheme not in ("http", "https") or not parts.hostname or not port_ok or " " in text:
            self.fail(path, "must be an http or https URL")
            return None
        if "@" in parts.netloc or parts.query or parts.fragment or "?" in text or "#" in text:
            self.fail(path, "must not contain credentials, a query or a fragment")
            return None
        if not parts.path.endswith("/"):
            self.fail(path, "must end with /")
            return None
        return text


@dataclass(frozen=True)
class ListenConfig:
    host: str
    port: int

    @property
    def is_loopback(self) -> bool:
        return ipaddress.ip_address(self.host).is_loopback

    def to_json(self) -> dict[str, Any]:
        return {"host": self.host, "port": self.port}


@dataclass(frozen=True)
class TgsConfig:
    url: str = "http://127.0.0.1:5000/"
    api_version: str = "10.14.1"
    timeout_seconds: float = 5.0
    verify_tls: bool = True
    cache_seconds: int = 30
    instance_permission_set_write_bit: int = 2

    @property
    def api_major(self) -> int:
        return int(self.api_version.split(".", 1)[0])

    def to_json(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "apiVersion": self.api_version,
            "timeoutSeconds": self.timeout_seconds,
            "verifyTls": self.verify_tls,
            "cacheSeconds": self.cache_seconds,
            "instancePermissionSetWriteBit": self.instance_permission_set_write_bit,
        }


@dataclass(frozen=True)
class ProcessingConfig:
    workers: int = 1
    niceness: int = 10
    pov_cache_mib: int = 2048

    @property
    def pov_cache_bytes(self) -> int:
        return self.pov_cache_mib * MIB

    def to_json(self) -> dict[str, Any]:
        return {"workers": self.workers, "niceness": self.niceness, "povCacheMiB": self.pov_cache_mib}


@dataclass(frozen=True)
class InstanceHostConfig:
    iid: int
    game_ports: tuple[int, ...]
    game_dir: str
    rsc_files: tuple[str, ...]
    interface: str = "any"
    capture_tool: str = "tcpdump"
    capture_path: str = "/usr/bin/tcpdump"
    capture_buffer_mib: int = 256
    capture_kernel_buffer_mib: int = 32
    capture_niceness: int = 0
    repo: str = ""

    @classmethod
    def from_json(cls, obj: Any, iid: int) -> InstanceHostConfig:
        check = _Check()
        instance = _instance(check, obj, check_iid(iid), f"instances.{iid}")
        check.done()
        return instance

    def to_json(self) -> dict[str, Any]:
        return {
            "gamePorts": list(self.game_ports),
            "interface": self.interface,
            "captureTool": self.capture_tool,
            "capturePath": self.capture_path,
            "captureBufferMiB": self.capture_buffer_mib,
            "captureKernelBufferMiB": self.capture_kernel_buffer_mib,
            "captureNiceness": self.capture_niceness,
            "gameDir": self.game_dir,
            "rscFiles": list(self.rsc_files),
            "repo": self.repo,
        }

    def capture_filter(self) -> str:
        return "tcp and (" + " or ".join(f"port {int(port)}" for port in self.game_ports) + ")"

    def rsc_paths(self) -> list[str]:
        return [os.path.join(self.game_dir, name) for name in self.rsc_files]


@dataclass(frozen=True)
class HostConfig:
    data_dir: str
    allowed_roots: tuple[str, ...]
    viewer_dir: str
    listen: ListenConfig = ListenConfig("127.0.0.1", 5182)
    game_listen: ListenConfig = ListenConfig("127.0.0.1", 5183)
    public_path: str = "/replays/"
    cors_origins: tuple[str, ...] = ()
    trusted_proxies: tuple[str, ...] = ("127.0.0.1/32", "::1/128")
    tgs: TgsConfig = TgsConfig()
    processing: ProcessingConfig = ProcessingConfig()
    instances: dict[int, InstanceHostConfig] = dataclasses.field(default_factory=dict)
    source: str = ""

    @classmethod
    def load(cls, path: str) -> HostConfig:
        try:
            with open(path, "rb") as fh:
                data = fh.read(CONFIG_MAX_BYTES + 1)
        except OSError as exc:
            raise ConfigError(f"cannot read {path}: {exc.strerror or exc.__class__.__name__}") from None
        if len(data) > CONFIG_MAX_BYTES:
            raise ConfigError(f"{path} is larger than {CONFIG_MAX_BYTES} bytes")
        try:
            obj = loads_strict(data.decode("utf-8-sig"))
        except ValueError as exc:
            raise ConfigError(f"{path} is not valid JSON: {exc}") from None
        return cls.from_json(obj, os.path.abspath(path))

    @classmethod
    def from_json(cls, obj: Any, source: str = "") -> HostConfig:
        if not isinstance(obj, dict):
            raise ConfigError("the configuration must be a JSON object")
        c = _Check()
        root = c.section(obj, "", _HOST_KEYS)
        listen = _listen(c, root.get("listen", {"host": "127.0.0.1", "port": 5182}), "listen")
        game_listen = _listen(c, root.get("gameListen", {"host": "127.0.0.1", "port": 5183}), "gameListen")
        if listen is not None and game_listen is not None and listen.port == game_listen.port:
            c.fail("gameListen.port", "must differ from listen.port")
        public_path = c.text(
            root.get("publicPath", "/replays/"), "publicPath", _PUBLIC_PATH_RE, 128,
            "must start and end with / and contain only A-Z a-z 0-9 / _ -",
        )
        if public_path is not None and "//" in public_path:
            c.fail("publicPath", "must not contain empty segments")
        data_dir = c.abspath(c.field(root, "dataDir", ""), "dataDir", allow_root=False)
        roots: list[str] = []
        for index, item in enumerate(c.array(c.field(root, "allowedRoots", ""), "allowedRoots", 1, 16) or []):
            value = c.abspath(item, f"allowedRoots[{index}]", allow_root=False)
            if value is not None:
                roots.append(value)
        viewer_dir = c.abspath(c.field(root, "viewerDir", ""), "viewerDir", allow_root=False)
        origins: list[str] = []
        for index, item in enumerate(c.array(root.get("corsOrigins", []), "corsOrigins", 0, 32) or []):
            value = c.text(item, f"corsOrigins[{index}]", None, 256)
            if value is not None and _ORIGIN_RE.match(value.lower()):
                origins.append(value.lower())
            elif value is not None:
                c.fail(f"corsOrigins[{index}]", "must be an origin like https://panel.example.org")
        proxies: list[str] = []
        for index, item in enumerate(c.array(root.get("trustedProxies", ["127.0.0.1", "::1"]), "trustedProxies", 0, 64) or []):
            value = c.network(item, f"trustedProxies[{index}]")
            if value is not None:
                proxies.append(value)
        tgs = _tgs(c, root.get("tgs", {}))
        processing = _processing(c, root.get("processing", {}))
        instances = _instances(c, root.get("instances", {}))
        if viewer_dir is not None:
            if data_dir is not None and is_within(data_dir, [viewer_dir]):
                c.fail("dataDir", "must not be inside viewerDir")
            for index, value in enumerate(roots):
                if is_within(value, [viewer_dir]):
                    c.fail(f"allowedRoots[{index}]", "must not be inside viewerDir")
        c.done()
        if not game_listen.is_loopback:
            log.warning("gameListen %s is not a loopback address; game tokens travel in plain HTTP", game_listen.host)
        return cls(
            data_dir=data_dir,
            allowed_roots=tuple(roots),
            viewer_dir=viewer_dir,
            listen=listen,
            game_listen=game_listen,
            public_path=public_path,
            cors_origins=tuple(origins),
            trusted_proxies=tuple(proxies),
            tgs=tgs,
            processing=processing,
            instances=instances,
            source=source,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "listen": self.listen.to_json(),
            "gameListen": self.game_listen.to_json(),
            "publicPath": self.public_path,
            "dataDir": self.data_dir,
            "allowedRoots": list(self.allowed_roots),
            "viewerDir": self.viewer_dir,
            "corsOrigins": list(self.cors_origins),
            "trustedProxies": list(self.trusted_proxies),
            "tgs": self.tgs.to_json(),
            "processing": self.processing.to_json(),
            "instances": {str(iid): item.to_json() for iid, item in sorted(self.instances.items())},
        }

    @property
    def instance_ids(self) -> list[int]:
        return sorted(self.instances)

    def instance(self, iid: Any) -> InstanceHostConfig | None:
        number = parse_iid(iid)
        return None if number is None else self.instances.get(number)

    def instance_paths(self, iid: int) -> InstancePaths:
        return instance_paths(self, iid)


def load_host_config(path: str) -> HostConfig:
    return HostConfig.load(path)


def _listen(c: _Check, value: Any, path: str) -> ListenConfig | None:
    start = len(c.errors)
    obj = c.section(value, path, ("host", "port"), required=True)
    host = c.ip(c.field(obj, "host", path), _join(path, "host"))
    port = c.integer(c.field(obj, "port", path), _join(path, "port"), 1, 65535)
    if len(c.errors) != start:
        return None
    return ListenConfig(host, port)


def _tgs(c: _Check, value: Any) -> TgsConfig | None:
    start = len(c.errors)
    d = TgsConfig()
    obj = c.section(value, "tgs", _TGS_KEYS)
    url = c.url(obj.get("url", d.url), "tgs.url")
    api_version = c.text(obj.get("apiVersion", d.api_version), "tgs.apiVersion", _API_VERSION_RE, 16, "must look like 10.14.1")
    timeout = c.number(obj.get("timeoutSeconds", d.timeout_seconds), "tgs.timeoutSeconds", 1, 60)
    verify = c.boolean(obj.get("verifyTls", d.verify_tls), "tgs.verifyTls")
    cache = c.integer(obj.get("cacheSeconds", d.cache_seconds), "tgs.cacheSeconds", 0, 300)
    bit = c.integer(
        obj.get("instancePermissionSetWriteBit", d.instance_permission_set_write_bit),
        "tgs.instancePermissionSetWriteBit", 1, 1 << 62,
    )
    if bit is not None and bit & (bit - 1):
        c.fail("tgs.instancePermissionSetWriteBit", "must be a single bit")
    if len(c.errors) != start:
        return None
    return TgsConfig(url, api_version, timeout, verify, cache, bit)


def _processing(c: _Check, value: Any) -> ProcessingConfig | None:
    start = len(c.errors)
    d = ProcessingConfig()
    obj = c.section(value, "processing", _PROCESSING_KEYS)
    workers = c.integer(obj.get("workers", d.workers), "processing.workers", 1, 16)
    niceness = c.integer(obj.get("niceness", d.niceness), "processing.niceness", 0, 19)
    cache = c.integer(obj.get("povCacheMiB", d.pov_cache_mib), "processing.povCacheMiB", 64, 1 << 20)
    if len(c.errors) != start:
        return None
    return ProcessingConfig(workers, niceness, cache)


def _instances(c: _Check, value: Any) -> dict[int, InstanceHostConfig]:
    out: dict[int, InstanceHostConfig] = {}
    if not isinstance(value, dict):
        c.fail("instances", "must be an object")
        return out
    if len(value) > 64:
        c.fail("instances", "must have at most 64 entries")
        return out
    for key, item in value.items():
        iid = parse_iid(key) if isinstance(key, str) and key == key.strip() else None
        if iid is None:
            c.fail(f"instances.{key}", "instance ids must be positive integers")
            continue
        instance = _instance(c, item, iid, f"instances.{key}")
        if instance is not None:
            out[iid] = instance
    return out


def _instance(c: _Check, value: Any, iid: int, path: str) -> InstanceHostConfig | None:
    start = len(c.errors)
    obj = c.section(value, path, _INSTANCE_KEYS, required=True)
    if len(c.errors) != start and not obj:
        return None
    ports: list[int] = []
    for index, item in enumerate(c.array(c.field(obj, "gamePorts", path), f"{path}.gamePorts", 1, 16) or []):
        port = c.integer(item, f"{path}.gamePorts[{index}]", 1, 65535)
        if port is not None and port in ports:
            c.fail(f"{path}.gamePorts[{index}]", "is a duplicate")
        elif port is not None:
            ports.append(port)
    tool = c.choice(obj.get("captureTool", "tcpdump"), f"{path}.captureTool", CAPTURE_TOOLS)
    interface = c.text(obj.get("interface", "any"), f"{path}.interface", None, 64)
    if interface is not None and interface != "any":
        pattern = _IFACE_DUMPCAP_RE if tool == "dumpcap" else _IFACE_RE
        if not pattern.match(interface) or interface.startswith("-"):
            c.fail(f"{path}.interface", "has an invalid format")
    default_path = "/usr/bin/" + (tool or "tcpdump")
    capture_path = c.abspath(obj.get("capturePath", default_path), f"{path}.capturePath", allow_root=False)
    buffer_mib = c.integer(obj.get("captureBufferMiB", 256), f"{path}.captureBufferMiB", 16, 4096)
    kernel_mib = c.integer(obj.get("captureKernelBufferMiB", 32), f"{path}.captureKernelBufferMiB", 1, 2048)
    niceness = c.integer(obj.get("captureNiceness", 0), f"{path}.captureNiceness", -20, 19)
    game_dir = c.abspath(c.field(obj, "gameDir", path), f"{path}.gameDir", allow_root=False)
    rsc: list[str] = []
    for index, item in enumerate(c.array(c.field(obj, "rscFiles", path), f"{path}.rscFiles", 1, 16) or []):
        name = c.text(item, f"{path}.rscFiles[{index}]", _RSC_NAME_RE, 128, "must be a plain file name")
        if name is not None and name in rsc:
            c.fail(f"{path}.rscFiles[{index}]", "is a duplicate")
        elif name is not None:
            rsc.append(name)
    repo = c.text(obj.get("repo", ""), f"{path}.repo", None, 200)
    if repo and not _REPO_RE.match(repo):
        c.fail(f"{path}.repo", "must look like owner/name")
    if len(c.errors) != start:
        return None
    return InstanceHostConfig(
        iid=iid,
        game_ports=tuple(ports),
        game_dir=game_dir,
        rsc_files=tuple(rsc),
        interface=interface,
        capture_tool=tool,
        capture_path=capture_path,
        capture_buffer_mib=buffer_mib,
        capture_kernel_buffer_mib=kernel_mib,
        capture_niceness=niceness,
        repo=repo,
    )


class RecordingPolicy(enum.IntEnum):
    DISABLED = 0
    ALWAYS = 1
    GAME_MASTER = 2
    TICKETS = 3
    GAME_MASTER_OR_TICKETS = 4


class LimitAction(enum.IntEnum):
    EVICT_OLDEST = 0
    STOP_RECORDING = 1


class ProcessingMode(enum.IntEnum):
    ON_ROUND_END = 0
    SCHEDULED = 1
    MANUAL = 2


SETTINGS_FIELDS: dict[str, str] = {
    "storagePath": "storage_path",
    "recordingEnabled": "recording_enabled",
    "policy": "policy",
    "ticketThreshold": "ticket_threshold",
    "retentionDays": "retention_days",
    "maxArchiveBytes": "max_archive_bytes",
    "onLimit": "on_limit",
    "minFreeBytes": "min_free_bytes",
    "flushIntervalSeconds": "flush_interval_seconds",
    "diskCheckIntervalSeconds": "disk_check_interval_seconds",
    "maintenanceIntervalMinutes": "maintenance_interval_minutes",
    "selfCheckIntervalMinutes": "self_check_interval_minutes",
    "processingMode": "processing_mode",
    "processingHour": "processing_hour",
    "keepRawDays": "keep_raw_days",
    "storeClientInput": "store_client_input",
    "xzDictMiB": "xz_dict_mib",
    "xzExtreme": "xz_extreme",
}
_INT_LIMITS: dict[str, tuple[int, int]] = {
    "ticketThreshold": (1, 1000),
    "retentionDays": (1, 360),
    "maxArchiveBytes": (GIB, 100 * TIB),
    "minFreeBytes": (0, 100 * TIB),
    "flushIntervalSeconds": (1, 300),
    "diskCheckIntervalSeconds": (5, 3600),
    "maintenanceIntervalMinutes": (1, 1440),
    "selfCheckIntervalMinutes": (5, 1440),
    "processingHour": (0, 23),
    "keepRawDays": (0, 360),
    "xzDictMiB": (8, 1536),
}
_ENUM_FIELDS: dict[str, type[enum.IntEnum]] = {
    "policy": RecordingPolicy,
    "onLimit": LimitAction,
    "processingMode": ProcessingMode,
}
_BOOL_FIELDS = frozenset(("recordingEnabled", "storeClientInput", "xzExtreme"))


@dataclass
class InstanceSettings:
    storage_path: str = ""
    recording_enabled: bool = True
    policy: RecordingPolicy = RecordingPolicy.GAME_MASTER_OR_TICKETS
    ticket_threshold: int = 3
    retention_days: int = 30
    max_archive_bytes: int = 100 * GIB
    on_limit: LimitAction = LimitAction.EVICT_OLDEST
    min_free_bytes: int = 20 * GIB
    flush_interval_seconds: int = 5
    disk_check_interval_seconds: int = 30
    maintenance_interval_minutes: int = 30
    self_check_interval_minutes: int = 60
    processing_mode: ProcessingMode = ProcessingMode.ON_ROUND_END
    processing_hour: int = 5
    keep_raw_days: int = 0
    store_client_input: bool = False
    xz_dict_mib: int = 64
    xz_extreme: bool = True

    def __post_init__(self) -> None:
        self.policy = RecordingPolicy(self.policy)
        self.on_limit = LimitAction(self.on_limit)
        self.processing_mode = ProcessingMode(self.processing_mode)

    @classmethod
    def defaults(cls, host: HostConfig, iid: int) -> InstanceSettings:
        return cls(storage_path=default_storage_path(host, iid))

    @classmethod
    def from_json(
        cls, obj: Any, host: HostConfig | None, iid: int, base: InstanceSettings | None = None
    ) -> InstanceSettings:
        if not isinstance(obj, dict):
            raise ConfigError("settings must be a JSON object")
        c = _Check()
        for key in obj:
            if key not in SETTINGS_FIELDS:
                c.fail(str(key), "unknown field")
        if base is not None:
            start = base
        elif host is not None:
            start = cls.defaults(host, iid)
        else:
            start = cls()
            if "storagePath" not in obj:
                c.fail("storagePath", "is required")
        values: dict[str, Any] = {}
        for name, attr in SETTINGS_FIELDS.items():
            if name not in obj:
                values[attr] = getattr(start, attr)
            elif name == "storagePath":
                values[attr] = _storage_path(c, obj[name], host)
            elif name in _BOOL_FIELDS:
                values[attr] = c.boolean(obj[name], name)
            elif name in _ENUM_FIELDS:
                values[attr] = c.enum(obj[name], name, _ENUM_FIELDS[name])
            else:
                lo, hi = _INT_LIMITS[name]
                values[attr] = c.integer(obj[name], name, lo, hi)
        c.done()
        return cls(**values)

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name, attr in SETTINGS_FIELDS.items():
            value = getattr(self, attr)
            out[name] = int(value) if isinstance(value, enum.IntEnum) else value
        return out

    @staticmethod
    def limits() -> dict[str, dict[str, int]]:
        out = {name: {"min": lo, "max": hi} for name, (lo, hi) in _INT_LIMITS.items()}
        for name, kind in _ENUM_FIELDS.items():
            out[name] = {"min": int(min(kind)), "max": int(max(kind))}
        return out

    def diff(self, other: InstanceSettings) -> dict[str, Any]:
        mine = self.to_json()
        return {name: value for name, value in other.to_json().items() if mine.get(name) != value}

    def copy(self) -> InstanceSettings:
        return dataclasses.replace(self)

    def layout(self) -> StorageLayout:
        return StorageLayout(os.path.normpath(self.storage_path))


def _storage_path(c: _Check, value: Any, host: HostConfig | None) -> str | None:
    path = c.abspath(value, "storagePath", allow_root=False)
    if path is None or host is None:
        return path
    if not is_within(path, host.allowed_roots):
        c.fail("storagePath", "must be inside one of allowedRoots")
        return None
    if is_within(host.data_dir, [path]) or is_within(path, [os.path.join(host.data_dir, "instances")]):
        c.fail("storagePath", "must not contain dataDir or lie inside dataDir/instances")
        return None
    if is_within(path, [host.viewer_dir]):
        c.fail("storagePath", "must not be inside viewerDir")
        return None
    return path


def default_storage_path(host: HostConfig, iid: int) -> str:
    return os.path.join(host.allowed_roots[0], str(check_iid(iid)))


@dataclass(frozen=True)
class InstancePaths:
    root: str
    settings: str
    grants: str
    selfcheck: str
    audit_dir: str


def instance_paths(host: HostConfig, iid: int) -> InstancePaths:
    root = os.path.join(host.data_dir, "instances", str(check_iid(iid)))
    return InstancePaths(
        root=root,
        settings=os.path.join(root, "settings.json"),
        grants=os.path.join(root, "grants.json"),
        selfcheck=os.path.join(root, "selfcheck.json"),
        audit_dir=os.path.join(root, "audit"),
    )


@dataclass(frozen=True)
class StorageLayout:
    root: str

    @property
    def spool_dir(self) -> str:
        return os.path.join(self.root, "spool")

    @property
    def spool_index(self) -> str:
        return os.path.join(self.root, "spool", "index.jsonl")

    @property
    def state_dir(self) -> str:
        return os.path.join(self.root, "state")

    @property
    def current_file(self) -> str:
        return os.path.join(self.root, "state", "current.json")

    @property
    def capture_file(self) -> str:
        return os.path.join(self.root, "state", "capture.json")

    @property
    def selfcheck_file(self) -> str:
        return os.path.join(self.root, "state", "selfcheck.json")

    @property
    def rounds_dir(self) -> str:
        return os.path.join(self.root, "rounds")

    @property
    def cas_dir(self) -> str:
        return os.path.join(self.root, "cas")

    @property
    def cas_current(self) -> str:
        return os.path.join(self.root, "cas", "current.json")

    @property
    def cache_dir(self) -> str:
        return os.path.join(self.root, "cache")

    @property
    def pov_cache_dir(self) -> str:
        return os.path.join(self.root, "cache", "pov")

    @property
    def tmp_dir(self) -> str:
        return os.path.join(self.root, "tmp")

    def round_dir(self, key: str) -> str:
        if not valid_round_key(key):
            raise ValueError("invalid round key")
        return os.path.join(self.rounds_dir, key)

    def directories(self) -> tuple[str, ...]:
        return (
            self.root, self.spool_dir, self.state_dir, self.rounds_dir,
            self.cas_dir, self.cache_dir, self.pov_cache_dir, self.tmp_dir,
        )

    def ensure(self) -> StorageLayout:
        for directory in self.directories():
            ensure_dir(directory)
        return self


def storage_layout(source: InstanceSettings | str) -> StorageLayout:
    root = source.storage_path if isinstance(source, InstanceSettings) else source
    return StorageLayout(os.path.normpath(root))


class SettingsStore:
    def __init__(self, host: HostConfig, iid: int) -> None:
        self.host = host
        self.iid = check_iid(iid)
        self._path = instance_paths(host, self.iid).settings
        self._lock = threading.Lock()
        self._stamp: Any = _MISSING
        self._settings: InstanceSettings | None = None
        self._errors: list[tuple[str, str]] | None = None

    @property
    def path(self) -> str:
        return self._path

    def exists(self) -> bool:
        return file_stamp(self._path) is not None

    def load(self) -> InstanceSettings:
        with self._lock:
            stamp = file_stamp(self._path)
            if stamp != self._stamp:
                self._reload(stamp)
            if self._errors is not None:
                raise ConfigError(self._errors)
            return dataclasses.replace(self._settings)

    def _reload(self, stamp: Any) -> None:
        self._stamp = stamp
        self._settings = None
        self._errors = None
        if stamp is None:
            self._settings = InstanceSettings.defaults(self.host, self.iid)
            return
        try:
            self._settings = InstanceSettings.from_json(read_json(self._path, None, strict=True), self.host, self.iid)
        except ConfigError as exc:
            self._errors = exc.errors
            log.error("settings of instance %d are invalid: %s", self.iid, exc)
        except (OSError, ValueError) as exc:
            self._errors = [("", f"cannot read the settings file: {exc.__class__.__name__}")]
            log.error("settings of instance %d are unreadable: %s", self.iid, exc.__class__.__name__)

    def save(self, settings: InstanceSettings) -> InstanceSettings:
        checked = InstanceSettings.from_json(settings.to_json(), self.host, self.iid)
        with self._lock:
            ensure_dir(os.path.dirname(self._path))
            atomic_write_json(self._path, checked.to_json(), indent=2)
            self._stamp = file_stamp(self._path)
            self._settings = checked
            self._errors = None
        return dataclasses.replace(checked)

    def ensure(self) -> InstanceSettings:
        if self.exists():
            return self.load()
        return self.save(InstanceSettings.defaults(self.host, self.iid))
