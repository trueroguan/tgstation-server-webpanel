export enum ReplayRights {
    View = 1,
    Play = 2,
    Record = 4,
    Process = 8,
    ManageArchives = 16,
    ManageSettings = 32
}

export enum RecordingPolicy {
    Disabled = 0,
    Always = 1,
    GameMaster = 2,
    Tickets = 3,
    GameMasterOrTickets = 4
}

export enum LimitAction {
    EvictOldest = 0,
    StopRecording = 1
}

export enum ProcessingMode {
    OnRoundEnd = 0,
    Scheduled = 1,
    Manual = 2
}

export type RecordingState = "recording" | "paused" | "disabled" | "error" | "idle" | "offline";

export type ReplayRoundStatus =
    | "open"
    | "closing"
    | "pending"
    | "discarded"
    | "processing"
    | "ready"
    | "failed";

export type ReplaySeverity = "critical" | "warning" | "info";

export interface ReplayFieldError {
    field: string;
    message: string;
}

export interface ReplayMe {
    userId: number;
    userName: string;
    permissionSetId: number;
    rights: number;
    canGrant: boolean;
}

export interface ReplayRoundSummary {
    key: string;
    map: string;
    bootedAt: number;
    startedAt: number | null;
    endedAt: number | null;
    status: ReplayRoundStatus;
    players: number;
    tickets: number;
    approved: boolean;
    bytes: number | null;
    expiresAt: number | null;
    povs: number;
}

export interface ReplayRecordingInfo {
    enabled: boolean;
    policy: RecordingPolicy;
    ticketThreshold: number;
    state: RecordingState;
    reason: string | null;
    openSessions: number;
    currentRound: ReplayRoundSummary | null;
}

export interface ReplayDiskInfo {
    path: string;
    freeBytes: number | null;
    totalBytes: number | null;
    minFreeBytes: number;
}

export interface ReplayArchiveUsage {
    usedBytes: number;
    maxBytes: number;
    rounds: number;
}

export interface ReplayProcessingInfo {
    queued: number;
    running: number;
}

export interface ReplaySelfCheckSummary {
    at: number | null;
    ok: boolean;
    critical: number;
    warnings: number;
}

export interface ReplayStatus {
    recording: ReplayRecordingInfo;
    disk: ReplayDiskInfo;
    archive: ReplayArchiveUsage;
    processing: ReplayProcessingInfo;
    selfCheck: ReplaySelfCheckSummary;
}

export interface ReplayHelpTicket {
    id: number;
    ckey: string;
    at: number;
}

export interface ReplayApproval {
    by: string;
    at: number;
    source: string;
    reason: string;
}

export interface ReplayLogin {
    at: number;
    address: string | null;
    marker: string;
}

export interface ReplayPlayer {
    ckey: string;
    key: string;
    characters: string[];
    firstSeen: number;
    lastSeen: number;
    addresses?: string[];
    logins?: ReplayLogin[];
}

export interface ReplaySession {
    file: string;
    client?: string;
    start: number;
    end: number | null;
    bytes: number;
    ckey: string | null;
    match: string | null;
}

export interface ReplayPov {
    id: string;
    ckey: string;
    member: string;
    bytes: number;
    sessions: number;
    start: number;
    end: number;
    resources: string[];
    missing: number;
}

export interface ReplayArchiveFile {
    file: string;
    bytes: number;
    sha256: string;
    rawBytes: number;
    members: number;
}

export interface ReplayRoundDetail {
    version: number;
    key: string;
    instance: number;
    rogueId: string;
    dbId: number | string | null;
    map: string;
    commit: string;
    bootedAt: number;
    startedAt: number | null;
    endedAt: number | null;
    status: ReplayRoundStatus;
    statusAt: number;
    error: string | null;
    policy: RecordingPolicy;
    ticketThreshold: number;
    tickets: ReplayHelpTicket[];
    approvals: ReplayApproval[];
    approved: boolean;
    players: ReplayPlayer[];
    sessions: ReplaySession[];
    povs: ReplayPov[];
    archive: ReplayArchiveFile | null;
    expiresAt: number | null;
    rawExpiresAt: number | null;
}

export interface ReplayTicketPending {
    ready: false;
    progress: number;
}

export interface ReplayTicketReady {
    ready: true;
    demoUrl: string;
    viewerUrl: string;
    expiresAt: number;
}

export type ReplayTicketResponse = ReplayTicketPending | ReplayTicketReady;

export interface ReplayProcessResult {
    queued: boolean;
}

export interface ReplaySettings {
    storagePath: string;
    recordingEnabled: boolean;
    policy: RecordingPolicy;
    ticketThreshold: number;
    retentionDays: number;
    maxArchiveBytes: number;
    onLimit: LimitAction;
    minFreeBytes: number;
    flushIntervalSeconds: number;
    diskCheckIntervalSeconds: number;
    maintenanceIntervalMinutes: number;
    selfCheckIntervalMinutes: number;
    processingMode: ProcessingMode;
    processingHour: number;
    keepRawDays: number;
    storeClientInput: boolean;
    xzDictMiB: number;
    xzExtreme: boolean;
}

export interface ReplayLimit {
    min: number;
    max: number;
}

export type ReplayLimits = Partial<Record<keyof ReplaySettings, ReplayLimit>>;

export interface ReplaySettingsResponse {
    settings: ReplaySettings;
    allowedRoots: string[];
    limits: ReplayLimits;
}

export interface ReplaySelfCheckItem {
    id: string;
    severity: ReplaySeverity;
    ok: boolean;
    message: string;
    details: unknown;
}

export interface ReplaySelfCheckReport {
    at: number | null;
    ok: boolean;
    critical: number;
    warnings: number;
    items: ReplaySelfCheckItem[];
}

export interface ReplayGrant {
    permissionSetId: number;
    rights: number;
}

export interface ReplayAuditEntry {
    at: number;
    actor: string;
    action: string;
    target: string;
    details: unknown;
}

export interface ReplayPaginated<T> {
    content: T[];
    totalPages: number;
    total: number | null;
}

export interface ReplayServerError {
    code: string;
    message: string;
    fields: ReplayFieldError[];
}

export const REPLAY_RIGHT_FLAGS: readonly ReplayRights[] = [
    ReplayRights.View,
    ReplayRights.Play,
    ReplayRights.Record,
    ReplayRights.Process,
    ReplayRights.ManageArchives,
    ReplayRights.ManageSettings
];

export const REPLAY_ALL_RIGHTS = REPLAY_RIGHT_FLAGS.reduce<number>((all, flag) => all | flag, 0);

export const SETTINGS_KEYS: readonly (keyof ReplaySettings)[] = [
    "storagePath",
    "recordingEnabled",
    "policy",
    "ticketThreshold",
    "retentionDays",
    "maxArchiveBytes",
    "onLimit",
    "minFreeBytes",
    "flushIntervalSeconds",
    "diskCheckIntervalSeconds",
    "maintenanceIntervalMinutes",
    "selfCheckIntervalMinutes",
    "processingMode",
    "processingHour",
    "keepRawDays",
    "storeClientInput",
    "xzDictMiB",
    "xzExtreme"
];

export const GIB = 1073741824;

const RECORDING_POLICIES: readonly RecordingPolicy[] = [
    RecordingPolicy.Disabled,
    RecordingPolicy.Always,
    RecordingPolicy.GameMaster,
    RecordingPolicy.Tickets,
    RecordingPolicy.GameMasterOrTickets
];

const LIMIT_ACTIONS: readonly LimitAction[] = [LimitAction.EvictOldest, LimitAction.StopRecording];

const PROCESSING_MODES: readonly ProcessingMode[] = [
    ProcessingMode.OnRoundEnd,
    ProcessingMode.Scheduled,
    ProcessingMode.Manual
];

const RECORDING_STATES: readonly RecordingState[] = [
    "recording",
    "paused",
    "disabled",
    "error",
    "idle",
    "offline"
];

const ROUND_STATUSES: readonly ReplayRoundStatus[] = [
    "open",
    "closing",
    "pending",
    "discarded",
    "processing",
    "ready",
    "failed"
];

const SEVERITIES: readonly ReplaySeverity[] = ["critical", "warning", "info"];

const TEXT_LIMIT = 4096;

const BYTE_UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];

const DATE_FORMAT: Intl.DateTimeFormatOptions = {
    day: "2-digit",
    year: "numeric",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZoneName: "short"
};

type JsonObject = Record<string, unknown>;

function isObject(value: unknown): value is JsonObject {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asObject(value: unknown): JsonObject {
    return isObject(value) ? value : {};
}

function isFiniteNumber(value: unknown): value is number {
    return typeof value === "number" && Number.isFinite(value);
}

function num(value: unknown): number {
    return isFiniteNumber(value) ? value : 0;
}

function optNum(value: unknown): number | null {
    return isFiniteNumber(value) ? value : null;
}

function text(value: unknown): string {
    return typeof value === "string" ? value.slice(0, TEXT_LIMIT) : "";
}

function optText(value: unknown): string | null {
    return typeof value === "string" ? value.slice(0, TEXT_LIMIT) : null;
}

function optionalText(value: unknown): string | undefined {
    return typeof value === "string" ? value.slice(0, TEXT_LIMIT) : undefined;
}

function texts(value: unknown): string[] {
    return Array.isArray(value)
        ? value.filter((item): item is string => typeof item === "string").map(text)
        : [];
}

function objects(value: unknown): JsonObject[] {
    return Array.isArray(value) ? value.filter(isObject) : [];
}

function count(value: unknown): number {
    if (Array.isArray(value)) return value.length;
    return Math.max(0, Math.floor(num(value)));
}

function pick<T>(allowed: readonly T[], value: unknown): T | undefined {
    return allowed.find(item => item === value);
}

function resourceKeys(value: unknown): string[] {
    const items: unknown[] = Array.isArray(value) ? value : [];
    const keys: string[] = [];
    for (const item of items) {
        if (typeof item === "string") {
            keys.push(item.slice(0, 16));
        } else if (isFiniteNumber(item)) {
            keys.push((item >>> 0).toString(16).padStart(8, "0"));
        }
    }
    return keys;
}

function roundSummary(value: JsonObject): ReplayRoundSummary {
    return {
        key: text(value.key),
        map: text(value.map),
        bootedAt: num(value.bootedAt),
        startedAt: optNum(value.startedAt),
        endedAt: optNum(value.endedAt),
        status: pick(ROUND_STATUSES, value.status) ?? "processing",
        players: count(value.players),
        tickets: count(value.tickets),
        approved: value.approved === true,
        bytes: optNum(value.bytes),
        expiresAt: optNum(value.expiresAt),
        povs: count(value.povs)
    };
}

function player(value: JsonObject): ReplayPlayer {
    return {
        ckey: text(value.ckey),
        key: text(value.key),
        characters: texts(value.characters),
        firstSeen: num(value.firstSeen),
        lastSeen: num(value.lastSeen),
        addresses: Array.isArray(value.addresses) ? texts(value.addresses) : undefined,
        logins: Array.isArray(value.logins)
            ? objects(value.logins).map(login => ({
                  at: num(login.at),
                  address: optText(login.address),
                  marker: text(login.marker)
              }))
            : undefined
    };
}

function session(value: JsonObject): ReplaySession {
    return {
        file: text(value.file),
        client: optionalText(value.client),
        start: num(value.start),
        end: optNum(value.end),
        bytes: num(value.bytes),
        ckey: optText(value.ckey),
        match: optText(value.match)
    };
}

function pov(value: JsonObject): ReplayPov {
    return {
        id: text(value.id),
        ckey: text(value.ckey),
        member: text(value.member),
        bytes: num(value.bytes),
        sessions: count(value.sessions),
        start: num(value.start),
        end: num(value.end),
        resources: resourceKeys(value.resources),
        missing: count(value.missing)
    };
}

function archiveFile(value: unknown): ReplayArchiveFile | null {
    if (!isObject(value)) return null;
    return {
        file: text(value.file),
        bytes: num(value.bytes),
        sha256: text(value.sha256),
        rawBytes: num(value.rawBytes),
        members: count(value.members)
    };
}

function dbId(value: unknown): number | string | null {
    if (isFiniteNumber(value)) return value;
    return typeof value === "string" ? value.slice(0, 64) : null;
}

export function parseMe(value: unknown): ReplayMe | undefined {
    if (!isObject(value)) return undefined;
    return {
        userId: num(value.userId),
        userName: text(value.userName),
        permissionSetId: num(value.permissionSetId),
        rights: Math.floor(num(value.rights)) & REPLAY_ALL_RIGHTS,
        canGrant: value.canGrant === true
    };
}

export function parseRoundSummary(value: unknown): ReplayRoundSummary | undefined {
    return isObject(value) ? roundSummary(value) : undefined;
}

export function parseStatus(value: unknown): ReplayStatus | undefined {
    if (!isObject(value)) return undefined;
    const recording = asObject(value.recording);
    const disk = asObject(value.disk);
    const archive = asObject(value.archive);
    const processing = asObject(value.processing);
    const selfCheck = asObject(value.selfCheck);
    const current = recording.currentRound;
    return {
        recording: {
            enabled: recording.enabled === true,
            policy: pick(RECORDING_POLICIES, recording.policy) ?? RecordingPolicy.Disabled,
            ticketThreshold: num(recording.ticketThreshold),
            state: pick(RECORDING_STATES, recording.state) ?? "offline",
            reason: optText(recording.reason),
            openSessions: count(recording.openSessions),
            currentRound: isObject(current) ? roundSummary(current) : null
        },
        disk: {
            path: text(disk.path),
            freeBytes: optNum(disk.freeBytes),
            totalBytes: optNum(disk.totalBytes),
            minFreeBytes: num(disk.minFreeBytes)
        },
        archive: {
            usedBytes: num(archive.usedBytes),
            maxBytes: num(archive.maxBytes),
            rounds: count(archive.rounds)
        },
        processing: {
            queued: count(processing.queued),
            running: count(processing.running)
        },
        selfCheck: {
            at: optNum(selfCheck.at),
            ok: selfCheck.ok === true,
            critical: count(selfCheck.critical),
            warnings: count(selfCheck.warnings)
        }
    };
}

function page<T>(value: unknown, map: (item: JsonObject) => T): ReplayPaginated<T> | undefined {
    if (!isObject(value) || !Array.isArray(value.content)) return undefined;
    return {
        content: objects(value.content).map(map),
        totalPages: Math.max(1, Math.floor(num(value.totalPages))),
        total: optNum(value.total)
    };
}

export function parseRoundPage(value: unknown): ReplayPaginated<ReplayRoundSummary> | undefined {
    return page(value, roundSummary);
}

export function parseRoundDetail(value: unknown): ReplayRoundDetail | undefined {
    if (!isObject(value) || typeof value.key !== "string") return undefined;
    return {
        version: num(value.version),
        key: text(value.key),
        instance: num(value.instance),
        rogueId: text(value.rogueId),
        dbId: dbId(value.dbId),
        map: text(value.map),
        commit: text(value.commit),
        bootedAt: num(value.bootedAt),
        startedAt: optNum(value.startedAt),
        endedAt: optNum(value.endedAt),
        status: pick(ROUND_STATUSES, value.status) ?? "processing",
        statusAt: num(value.statusAt),
        error: optText(value.error),
        policy: pick(RECORDING_POLICIES, value.policy) ?? RecordingPolicy.Disabled,
        ticketThreshold: num(value.ticketThreshold),
        tickets: objects(value.tickets).map(ticket => ({
            id: num(ticket.id),
            ckey: text(ticket.ckey),
            at: num(ticket.at)
        })),
        approvals: objects(value.approvals).map(approval => ({
            by: text(approval.by),
            at: num(approval.at),
            source: text(approval.source),
            reason: text(approval.reason)
        })),
        approved: value.approved === true,
        players: objects(value.players).map(player),
        sessions: objects(value.sessions).map(session),
        povs: objects(value.povs).map(pov),
        archive: archiveFile(value.archive),
        expiresAt: optNum(value.expiresAt),
        rawExpiresAt: optNum(value.rawExpiresAt)
    };
}

export function parseTicket(value: unknown, status: number): ReplayTicketResponse | undefined {
    if (!isObject(value)) return undefined;
    const demoUrl = value.demoUrl;
    const viewerUrl = value.viewerUrl;
    if (status === 200 && value.ready === true) {
        if (typeof demoUrl !== "string" || typeof viewerUrl !== "string") return undefined;
        if (demoUrl.length > TEXT_LIMIT || viewerUrl.length > TEXT_LIMIT) return undefined;
        return { ready: true, demoUrl, viewerUrl, expiresAt: num(value.expiresAt) };
    }
    return { ready: false, progress: Math.min(1, Math.max(0, num(value.progress))) };
}

export function parseProcess(value: unknown): ReplayProcessResult | undefined {
    return isObject(value) ? { queued: value.queued === true } : undefined;
}

export function parseSettings(value: unknown): ReplaySettings | undefined {
    if (!isObject(value)) return undefined;
    const storagePath = value.storagePath;
    const policy = pick(RECORDING_POLICIES, value.policy);
    const onLimit = pick(LIMIT_ACTIONS, value.onLimit);
    const processingMode = pick(PROCESSING_MODES, value.processingMode);
    const flags = [value.recordingEnabled, value.storeClientInput, value.xzExtreme];
    const numbers = [
        value.ticketThreshold,
        value.retentionDays,
        value.maxArchiveBytes,
        value.minFreeBytes,
        value.flushIntervalSeconds,
        value.diskCheckIntervalSeconds,
        value.maintenanceIntervalMinutes,
        value.selfCheckIntervalMinutes,
        value.processingHour,
        value.keepRawDays,
        value.xzDictMiB
    ];
    if (
        typeof storagePath !== "string" ||
        policy === undefined ||
        onLimit === undefined ||
        processingMode === undefined ||
        !flags.every(flag => typeof flag === "boolean") ||
        !numbers.every(isFiniteNumber)
    ) {
        return undefined;
    }
    return {
        storagePath,
        recordingEnabled: value.recordingEnabled === true,
        policy,
        ticketThreshold: num(value.ticketThreshold),
        retentionDays: num(value.retentionDays),
        maxArchiveBytes: num(value.maxArchiveBytes),
        onLimit,
        minFreeBytes: num(value.minFreeBytes),
        flushIntervalSeconds: num(value.flushIntervalSeconds),
        diskCheckIntervalSeconds: num(value.diskCheckIntervalSeconds),
        maintenanceIntervalMinutes: num(value.maintenanceIntervalMinutes),
        selfCheckIntervalMinutes: num(value.selfCheckIntervalMinutes),
        processingMode,
        processingHour: num(value.processingHour),
        keepRawDays: num(value.keepRawDays),
        storeClientInput: value.storeClientInput === true,
        xzDictMiB: num(value.xzDictMiB),
        xzExtreme: value.xzExtreme === true
    };
}

export function parseSettingsResponse(value: unknown): ReplaySettingsResponse | undefined {
    if (!isObject(value)) return undefined;
    const settings = parseSettings(value.settings);
    if (!settings) return undefined;
    const rawLimits = asObject(value.limits);
    const limits: ReplayLimits = {};
    for (const key of SETTINGS_KEYS) {
        const limit = asObject(rawLimits[key]);
        const min = limit.min;
        const max = limit.max;
        if (isFiniteNumber(min) && isFiniteNumber(max)) {
            limits[key] = { min, max };
        }
    }
    return { settings, allowedRoots: texts(value.allowedRoots), limits };
}

export function parseSelfCheck(value: unknown): ReplaySelfCheckReport | undefined {
    if (!isObject(value)) return undefined;
    return {
        at: optNum(value.at),
        ok: value.ok === true,
        critical: count(value.critical),
        warnings: count(value.warnings),
        items: objects(value.items).map(item => ({
            id: text(item.id),
            severity: pick(SEVERITIES, item.severity) ?? "info",
            ok: item.ok === true,
            message: text(item.message),
            details: item.details
        }))
    };
}

function grant(value: JsonObject): ReplayGrant | undefined {
    const permissionSetId = value.permissionSetId;
    const rights = value.rights;
    if (!Number.isSafeInteger(permissionSetId) || !isFiniteNumber(rights)) return undefined;
    return { permissionSetId: num(permissionSetId), rights: Math.floor(rights) & REPLAY_ALL_RIGHTS };
}

export function parseGrant(value: unknown): ReplayGrant | undefined {
    return isObject(value) ? grant(value) : undefined;
}

export function parseGrants(value: unknown): ReplayGrant[] | undefined {
    if (!isObject(value) || !Array.isArray(value.grants)) return undefined;
    const grants: ReplayGrant[] = [];
    for (const item of objects(value.grants)) {
        const parsed = grant(item);
        if (parsed) grants.push(parsed);
    }
    return grants;
}

export function parseAuditPage(value: unknown): ReplayPaginated<ReplayAuditEntry> | undefined {
    return page(value, entry => ({
        at: num(entry.at),
        actor: text(entry.actor),
        action: text(entry.action),
        target: text(entry.target),
        details: entry.details
    }));
}

export function parseServerError(value: unknown): ReplayServerError | undefined {
    const error = asObject(asObject(value).error);
    if (typeof error.code !== "string" && typeof error.message !== "string") return undefined;
    const fields = objects(error.fields).slice(0, 50);
    return {
        code: text(error.code).slice(0, 64),
        message: text(error.message).slice(0, 500),
        fields: fields.map(field => ({
            field: text(field.field).slice(0, 128),
            message: text(field.message).slice(0, 500)
        }))
    };
}

export function hasReplayRights(rights: number, required: number): boolean {
    return (rights & required) === required;
}

export function formatBytes(value: number | null | undefined): string {
    if (!isFiniteNumber(value) || value < 0) return "-";
    let amount = value;
    let unit = 0;
    while (amount >= 1024 && unit < BYTE_UNITS.length - 1) {
        amount /= 1024;
        unit += 1;
    }
    const digits = unit === 0 || amount >= 100 ? 0 : amount >= 10 ? 1 : 2;
    return `${amount.toFixed(digits)} ${BYTE_UNITS[unit]}`;
}

export function formatTimestamp(seconds: number | null | undefined): string {
    if (!isFiniteNumber(seconds) || seconds <= 0) return "-";
    return new Date(seconds * 1000).toLocaleString("en-CA", DATE_FORMAT);
}

export function formatDuration(start: number | null, end: number | null): string {
    if (!isFiniteNumber(start) || !isFiniteNumber(end) || start <= 0 || end < start) return "-";
    const total = Math.round(end - start);
    const hours = Math.floor(total / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    if (hours > 0) return `${hours}h ${minutes}m`;
    if (minutes > 0) return `${minutes}m ${total % 60}s`;
    return `${total}s`;
}

export function formatDetails(value: unknown): string {
    if (value === null || value === undefined) return "";
    if (typeof value === "string") return value.slice(0, TEXT_LIMIT);
    const serialized = JSON.stringify(value);
    return typeof serialized === "string" ? serialized.slice(0, TEXT_LIMIT) : "";
}
