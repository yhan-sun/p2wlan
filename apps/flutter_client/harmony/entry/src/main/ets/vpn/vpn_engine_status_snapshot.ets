import { fileIo } from '@kit.CoreFileKit';
import { util } from '@kit.ArkTS';

export const P2WLAN_VPN_ENGINE_STATUS_SCHEMA_VERSION: number = 2;
export const P2WLAN_VPN_ENGINE_STATUS_MAX_BYTES: number = 16 * 1024;
export const P2WLAN_VPN_ENGINE_STATUS_FILE: string = 'vpn-engine-status-v1.json';

export type P2wlanVpnEngineStatusValueV1 =
  | 'starting'
  | 'ready'
  | 'stopping'
  | 'stopped'
  | 'draining'
  | 'failed';

export type P2wlanVpnOperationV2 = 'start' | 'stop';

export interface P2wlanVpnEngineStatusIdentityV1 {
  instanceId: string;
  generation: number;
}

export interface P2wlanVpnEngineStatusSnapshotV1 {
  schemaVersion: number;
  revision: number;
  updatedAtEpochMs: number;
  requestId: string;
  operation: P2wlanVpnOperationV2;
  settingsRevision: number;
  identity: P2wlanVpnEngineStatusIdentityV1 | null;
  status: P2wlanVpnEngineStatusValueV1;
  code?: string;
}

export interface P2wlanVpnStopPredecessorV1 {
  requestId: string;
  afterStatusRevision: number;
}

export class P2wlanVpnEngineStatusSnapshotError extends Error {
  code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

const REQUIRED_FIELDS: Array<string> = [
  'schemaVersion',
  'revision',
  'updatedAtEpochMs',
  'requestId',
  'operation',
  'settingsRevision',
  'identity',
  'status'
];
const STATUS_VALUES: Array<string> = [
  'starting',
  'ready',
  'stopping',
  'stopped',
  'draining',
  'failed'
];
let temporaryFileSequence: number = 0;

function isRecord(value: Object): boolean {
  return value != undefined && typeof value == 'object' && !Array.isArray(value);
}

function hasExactKeys(value: Object, expected: Array<string>): boolean {
  if (!isRecord(value)) {
    return false;
  }
  const actual: Array<string> = Object.keys(value);
  if (actual.length != expected.length) {
    return false;
  }
  for (const key of actual) {
    if (expected.indexOf(key) < 0) {
      return false;
    }
  }
  return true;
}

function validIdentity(value: Object | null): boolean {
  if (value == null) {
    return true;
  }
  if (!hasExactKeys(value, ['instanceId', 'generation'])) {
    return false;
  }
  const identity = value as P2wlanVpnEngineStatusIdentityV1;
  return typeof identity.instanceId == 'string' &&
    identity.instanceId.length > 0 && identity.instanceId.length <= 256 &&
    identity.instanceId.trim() == identity.instanceId &&
    identity.instanceId.indexOf('\0') < 0 &&
    Number.isInteger(identity.generation) && identity.generation > 0 &&
    identity.generation <= 9007199254740991;
}

export function parseP2wlanVpnEngineStatusSnapshot(
  source: string
): P2wlanVpnEngineStatusSnapshotV1 {
  try {
    const parsed: Object = JSON.parse(source);
    const fields = Object.keys(parsed);
    const hasCode = fields.indexOf('code') >= 0;
    const expectedFields = REQUIRED_FIELDS.slice();
    if (hasCode) {
      expectedFields.push('code');
    }
    if (!hasExactKeys(parsed, expectedFields)) {
      throw new P2wlanVpnEngineStatusSnapshotError(
        'VPN_ENGINE_STATUS_SNAPSHOT_INVALID'
      );
    }
    const snapshot = parsed as P2wlanVpnEngineStatusSnapshotV1;
    if (snapshot.schemaVersion != P2WLAN_VPN_ENGINE_STATUS_SCHEMA_VERSION ||
        !Number.isInteger(snapshot.revision) || snapshot.revision <= 0 ||
        snapshot.revision > 9007199254740991 ||
        !Number.isInteger(snapshot.updatedAtEpochMs) || snapshot.updatedAtEpochMs <= 0 ||
        snapshot.updatedAtEpochMs > 9007199254740991 ||
        !validRequestId(snapshot.requestId) ||
        (snapshot.operation != 'start' && snapshot.operation != 'stop') ||
        !Number.isInteger(snapshot.settingsRevision) ||
        snapshot.settingsRevision <= 0 ||
        snapshot.settingsRevision > 9007199254740991 ||
        !validIdentity(snapshot.identity as Object | null) ||
        STATUS_VALUES.indexOf(snapshot.status) < 0 ||
        (hasCode && (typeof snapshot.code != 'string' ||
          !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(snapshot.code)))) {
      throw new P2wlanVpnEngineStatusSnapshotError(
        'VPN_ENGINE_STATUS_SNAPSHOT_INVALID'
      );
    }
    return snapshot;
  } catch (error) {
    if (error instanceof P2wlanVpnEngineStatusSnapshotError) {
      throw error;
    }
    throw new P2wlanVpnEngineStatusSnapshotError(
      'VPN_ENGINE_STATUS_SNAPSHOT_INVALID'
    );
  }
}

function validRequestId(value: string): boolean {
  return typeof value == 'string' && value.length > 0 && value.length <= 128 &&
    /^[A-Za-z0-9._:-]+$/.test(value);
}

function readExistingSnapshot(path: string): P2wlanVpnEngineStatusSnapshotV1 | null {
  try {
    if (!fileIo.accessSync(path, fileIo.AccessModeType.EXIST)) {
      return null;
    }
    const stat = fileIo.statSync(path);
    if (!stat.isFile() || !Number.isInteger(stat.size) || stat.size <= 0) {
      throw new P2wlanVpnEngineStatusSnapshotError(
        'VPN_ENGINE_STATUS_SNAPSHOT_INVALID'
      );
    }
    if (stat.size > P2WLAN_VPN_ENGINE_STATUS_MAX_BYTES) {
      throw new P2wlanVpnEngineStatusSnapshotError(
        'VPN_ENGINE_STATUS_SNAPSHOT_TOO_LARGE'
      );
    }
    return parseP2wlanVpnEngineStatusSnapshot(
      fileIo.readTextSync(path, { encoding: 'utf-8' })
    );
  } catch (error) {
    if (error instanceof P2wlanVpnEngineStatusSnapshotError) {
      throw error;
    }
    throw new P2wlanVpnEngineStatusSnapshotError(
      'VPN_ENGINE_STATUS_SNAPSHOT_READ_FAILED'
    );
  }
}

function writeAtomically(path: string, source: string): void {
  const encoded: Uint8Array = util.TextEncoder.create('utf-8').encodeInto(source);
  if (encoded.length <= 0 || encoded.length > P2WLAN_VPN_ENGINE_STATUS_MAX_BYTES) {
    throw new P2wlanVpnEngineStatusSnapshotError(
      'VPN_ENGINE_STATUS_SNAPSHOT_TOO_LARGE'
    );
  }
  const sequence = temporaryFileSequence++;
  const temporaryPath = `${path}.${Date.now()}.${sequence}.tmp`;
  let fd: number = -1;
  try {
    fd = fileIo.openSync(
      temporaryPath,
      fileIo.OpenMode.WRITE_ONLY | fileIo.OpenMode.CREATE |
        fileIo.OpenMode.TRUNC | fileIo.OpenMode.NOFOLLOW
    ).fd;
    let offset: number = 0;
    while (offset < encoded.length) {
      const written = fileIo.writeSync(fd, encoded.buffer as ArrayBuffer, {
        offset: offset,
        length: encoded.length - offset
      });
      if (written <= 0) {
        throw new P2wlanVpnEngineStatusSnapshotError(
          'VPN_ENGINE_STATUS_SNAPSHOT_WRITE_FAILED'
        );
      }
      offset += written;
    }
    fileIo.fsyncSync(fd);
    fileIo.closeSync(fd);
    fd = -1;
    fileIo.renameSync(temporaryPath, path);
  } catch (_error) {
    if (fd >= 0) {
      try {
        fileIo.closeSync(fd);
      } catch (_closeError) {
        // Keep the stable public failure code below.
      }
    }
    try {
      fileIo.unlinkSync(temporaryPath);
    } catch (_unlinkError) {
      // A leftover temporary file is never read as the current snapshot.
    }
    throw new P2wlanVpnEngineStatusSnapshotError(
      'VPN_ENGINE_STATUS_SNAPSHOT_WRITE_FAILED'
    );
  }
}

/** Reads one bounded, versioned status snapshot from the app-private directory. */
export function readP2wlanVpnEngineStatusSnapshot(
  filesDir: string
): P2wlanVpnEngineStatusSnapshotV1 {
  if (typeof filesDir != 'string' || filesDir.length == 0 ||
      filesDir.length > 4096 || filesDir.trim() != filesDir ||
      filesDir.indexOf('\0') >= 0) {
    throw new P2wlanVpnEngineStatusSnapshotError(
      'VPN_ENGINE_STATUS_SNAPSHOT_READ_FAILED'
    );
  }
  const path = `${filesDir}/p2wlan/${P2WLAN_VPN_ENGINE_STATUS_FILE}`;
  const snapshot = readExistingSnapshot(path);
  if (snapshot == null) {
    throw new P2wlanVpnEngineStatusSnapshotError(
      'VPN_ENGINE_STATUS_SNAPSHOT_READ_FAILED'
    );
  }
  return snapshot;
}

/** Reads a current status when one exists, preserving the first-start case. */
export function readP2wlanVpnEngineStatusSnapshotIfPresent(
  filesDir: string
): P2wlanVpnEngineStatusSnapshotV1 | null {
  if (typeof filesDir != 'string' || filesDir.length == 0 ||
      filesDir.length > 4096 || filesDir.trim() != filesDir ||
      filesDir.indexOf('\0') >= 0) {
    throw new P2wlanVpnEngineStatusSnapshotError(
      'VPN_ENGINE_STATUS_SNAPSHOT_READ_FAILED'
    );
  }
  return readExistingSnapshot(
    `${filesDir}/p2wlan/${P2WLAN_VPN_ENGINE_STATUS_FILE}`
  );
}

/** Finalizes a stop only after the extension stopped its engine and the system accepted the stop request. */
export function finalizeP2wlanVpnEngineStopSnapshot(
  filesDir: string,
  requestId: string,
  settingsRevision: number
): P2wlanVpnEngineStatusSnapshotV1 {
  const current = readP2wlanVpnEngineStatusSnapshotIfPresent(filesDir);
  if (current == null || current.requestId != requestId ||
      current.operation != 'stop' || current.settingsRevision != settingsRevision) {
    throw new P2wlanVpnEngineStatusSnapshotError(
      'VPN_ENGINE_STATUS_SNAPSHOT_STALE'
    );
  }
  if (current.status == 'stopped') {
    return current;
  }
  if (current.status != 'stopping' || current.code != 'ENGINE_NATIVE_STOPPED') {
    throw new P2wlanVpnEngineStatusSnapshotError(
      'VPN_ENGINE_STATUS_STOP_NOT_CONFIRMED'
    );
  }
  return publishP2wlanVpnEngineStatusSnapshot(
    filesDir,
    requestId,
    'stop',
    settingsRevision,
    'stopped',
    current.identity,
    'ENGINE_STOPPED'
  );
}

/** Waits for native stop confirmation in the same session before publishing stopped. */
export async function waitForAndFinalizeP2wlanVpnEngineStopSnapshot(
  filesDir: string,
  requestId: string,
  settingsRevision: number,
  timeoutMs: number = 15000,
  predecessor?: P2wlanVpnStopPredecessorV1
): Promise<P2wlanVpnEngineStatusSnapshotV1> {
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 60000 ||
      (predecessor != undefined && (!validRequestId(predecessor.requestId) ||
        !Number.isInteger(predecessor.afterStatusRevision) ||
        predecessor.afterStatusRevision <= 0 ||
        predecessor.afterStatusRevision > 9007199254740991))) {
    throw new P2wlanVpnEngineStatusSnapshotError(
      'VPN_ENGINE_STATUS_STOP_NOT_CONFIRMED'
    );
  }
  const deadline = Date.now() + timeoutMs;
  while (true) {
    const current = readP2wlanVpnEngineStatusSnapshotIfPresent(filesDir);
    if (current == null || current.settingsRevision != settingsRevision) {
      throw new P2wlanVpnEngineStatusSnapshotError(
        'VPN_ENGINE_STATUS_SNAPSHOT_STALE'
      );
    }
    if (current.requestId != requestId) {
      // The system may accept stop before onDestroy publishes the stop session.
      // Wait only for the exact start session that the caller asked to stop.
      if (predecessor == undefined || current.requestId != predecessor.requestId ||
          current.operation != 'start' ||
          current.revision < predecessor.afterStatusRevision) {
        throw new P2wlanVpnEngineStatusSnapshotError(
          'VPN_ENGINE_STATUS_SNAPSHOT_STALE'
        );
      }
    } else if (current.operation != 'stop') {
      throw new P2wlanVpnEngineStatusSnapshotError(
        'VPN_ENGINE_STATUS_SNAPSHOT_STALE'
      );
    } else if (current.status == 'stopped') {
      return current;
    } else if (current.status == 'stopping' && current.code == 'ENGINE_NATIVE_STOPPED') {
      return finalizeP2wlanVpnEngineStopSnapshot(filesDir, requestId, settingsRevision);
    } else if (current.status == 'draining' || current.status == 'failed') {
      throw new P2wlanVpnEngineStatusSnapshotError(
        'VPN_ENGINE_STATUS_STOP_NOT_CONFIRMED'
      );
    }
    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) {
      break;
    }
    await new Promise<void>((resolve: () => void) => {
      setTimeout(resolve, Math.min(100, remainingMs));
    });
  }
  throw new P2wlanVpnEngineStatusSnapshotError(
    'VPN_ENGINE_STATUS_STOP_NOT_CONFIRMED'
  );
}

/** Publishes a status transition without carrying secrets, descriptors, or paths. */
export function publishP2wlanVpnEngineStatusSnapshot(
  filesDir: string,
  requestId: string,
  operation: P2wlanVpnOperationV2,
  settingsRevision: number,
  status: P2wlanVpnEngineStatusValueV1,
  identity: P2wlanVpnEngineStatusIdentityV1 | null,
  code?: string,
  claimNewSession: boolean = false
): P2wlanVpnEngineStatusSnapshotV1 {
  if (typeof filesDir != 'string' || filesDir.length == 0 ||
      filesDir.length > 4096 || filesDir.trim() != filesDir ||
      filesDir.indexOf('\0') >= 0 || !validRequestId(requestId) ||
      (operation != 'start' && operation != 'stop') ||
      !Number.isInteger(settingsRevision) || settingsRevision <= 0 ||
      settingsRevision > 9007199254740991 ||
      STATUS_VALUES.indexOf(status) < 0 ||
      !validIdentity(identity as Object | null) ||
      (code != undefined && (typeof code != 'string' ||
        !/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(code)))) {
    throw new P2wlanVpnEngineStatusSnapshotError(
      'VPN_ENGINE_STATUS_SNAPSHOT_INVALID'
    );
  }

  const directory = `${filesDir}/p2wlan`;
  const path = `${directory}/${P2WLAN_VPN_ENGINE_STATUS_FILE}`;
  try {
    if (!fileIo.accessSync(directory, fileIo.AccessModeType.EXIST)) {
      fileIo.mkdirSync(directory, true);
    }
    const previous = readExistingSnapshot(path);
    if (previous != null && previous.requestId != requestId && !claimNewSession) {
      throw new P2wlanVpnEngineStatusSnapshotError(
        'VPN_ENGINE_STATUS_SNAPSHOT_STALE'
      );
    }
    const revision = previous == null ? 1 : previous.revision + 1;
    if (revision <= 0 || revision > 9007199254740991) {
      throw new P2wlanVpnEngineStatusSnapshotError(
        'VPN_ENGINE_STATUS_SNAPSHOT_REVISION_INVALID'
      );
    }
    const snapshot: P2wlanVpnEngineStatusSnapshotV1 = {
      schemaVersion: P2WLAN_VPN_ENGINE_STATUS_SCHEMA_VERSION,
      revision: revision,
      updatedAtEpochMs: Date.now(),
      requestId: requestId,
      operation: operation,
      settingsRevision: settingsRevision,
      identity: identity,
      status: status
    };
    if (code != undefined) {
      snapshot.code = code;
    }
    const source = JSON.stringify(snapshot);
    writeAtomically(path, source);
    return snapshot;
  } catch (error) {
    if (error instanceof P2wlanVpnEngineStatusSnapshotError) {
      throw error;
    }
    throw new P2wlanVpnEngineStatusSnapshotError(
      'VPN_ENGINE_STATUS_SNAPSHOT_WRITE_FAILED'
    );
  }
}
