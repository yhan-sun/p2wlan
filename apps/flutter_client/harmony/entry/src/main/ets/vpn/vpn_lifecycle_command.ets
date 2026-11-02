import { fileIo } from '@kit.CoreFileKit';
import { util } from '@kit.ArkTS';

const STOP_REQUEST_FILE: string = 'vpn-stop-request-v1.json';
const MAX_COMMAND_BYTES: number = 4096;
let temporaryFileSequence: number = 0;

export interface P2wlanVpnStopCommandV1 {
  schemaVersion: number;
  operation: 'stop';
  requestId: string;
  expectedStatusRequestId: string;
  settingsRevision: number;
  afterStatusRevision: number;
  requestedAtEpochMs: number;
}

function hasExactKeys(value: Object, expected: Array<string>): boolean {
  if (value == undefined || typeof value != 'object' || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value);
  return actual.length == expected.length &&
    actual.every((key: string) => expected.indexOf(key) >= 0);
}

function validStopCommand(value: Object): boolean {
  if (!hasExactKeys(value, [
      'schemaVersion', 'operation', 'requestId', 'settingsRevision',
      'expectedStatusRequestId', 'afterStatusRevision', 'requestedAtEpochMs'])) {
    return false;
  }
  const command = value as P2wlanVpnStopCommandV1;
  const now = Date.now();
  return command.schemaVersion == 1 && command.operation == 'stop' &&
    typeof command.requestId == 'string' && command.requestId.length > 0 &&
    command.requestId.length <= 128 &&
    /^[A-Za-z0-9._:-]+$/.test(command.requestId) &&
    typeof command.expectedStatusRequestId == 'string' &&
    command.expectedStatusRequestId.length > 0 &&
    command.expectedStatusRequestId.length <= 128 &&
    /^[A-Za-z0-9._:-]+$/.test(command.expectedStatusRequestId) &&
    Number.isInteger(command.settingsRevision) && command.settingsRevision > 0 &&
    Number.isInteger(command.afterStatusRevision) && command.afterStatusRevision > 0 &&
    Number.isInteger(command.requestedAtEpochMs) &&
    now - command.requestedAtEpochMs <= 120000 &&
    command.requestedAtEpochMs - now <= 5000;
}

function commandPath(filesDir: string): string {
  if (typeof filesDir != 'string' || filesDir.length == 0 ||
      filesDir.length > 4096 || filesDir.trim() != filesDir ||
      filesDir.indexOf('\0') >= 0) {
    throw new Error('VPN_OPERATION_REQUEST_INVALID');
  }
  return `${filesDir}/p2wlan/${STOP_REQUEST_FILE}`;
}

function writeAtomically(path: string, source: string): void {
  const encoded = util.TextEncoder.create('utf-8').encodeInto(source);
  if (encoded.length <= 0 || encoded.length > MAX_COMMAND_BYTES) {
    throw new Error('VPN_OPERATION_REQUEST_TOO_LARGE');
  }
  const temporaryPath = `${path}.${Date.now()}.${temporaryFileSequence++}.tmp`;
  let fd: number = -1;
  try {
    fd = fileIo.openSync(
      temporaryPath,
      fileIo.OpenMode.WRITE_ONLY | fileIo.OpenMode.CREATE |
        fileIo.OpenMode.TRUNC | fileIo.OpenMode.NOFOLLOW
    ).fd;
    let offset = 0;
    while (offset < encoded.length) {
      const written = fileIo.writeSync(fd, encoded.buffer as ArrayBuffer, {
        offset: offset,
        length: encoded.length - offset
      });
      if (written <= 0) {
        throw new Error('VPN_OPERATION_REQUEST_WRITE_FAILED');
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
        // Preserve the stable request-write failure.
      }
    }
    try {
      fileIo.unlinkSync(temporaryPath);
    } catch (_unlinkError) {
      // Temporary requests are never read as the current command.
    }
    throw new Error('VPN_OPERATION_REQUEST_WRITE_FAILED');
  }
}

export function publishP2wlanVpnStopCommand(
  filesDir: string,
  requestId: string,
  expectedStatusRequestId: string,
  settingsRevision: number,
  afterStatusRevision: number
): void {
  const command: P2wlanVpnStopCommandV1 = {
    schemaVersion: 1,
    operation: 'stop',
    requestId: requestId,
    expectedStatusRequestId: expectedStatusRequestId,
    settingsRevision: settingsRevision,
    afterStatusRevision: afterStatusRevision,
    requestedAtEpochMs: Date.now()
  };
  if (!validStopCommand(command)) {
    throw new Error('VPN_OPERATION_REQUEST_INVALID');
  }
  const path = commandPath(filesDir);
  const directory = `${filesDir}/p2wlan`;
  if (!fileIo.accessSync(directory, fileIo.AccessModeType.EXIST)) {
    fileIo.mkdirSync(directory, true);
  }
  writeAtomically(path, JSON.stringify(command));
}

export function consumeP2wlanVpnStopCommand(
  filesDir: string
): P2wlanVpnStopCommandV1 | null {
  const path = commandPath(filesDir);
  try {
    if (!fileIo.accessSync(path, fileIo.AccessModeType.EXIST)) {
      return null;
    }
    const stat = fileIo.statSync(path);
    if (!stat.isFile() || stat.size <= 0 || stat.size > MAX_COMMAND_BYTES) {
      fileIo.unlinkSync(path);
      return null;
    }
    const source = fileIo.readTextSync(path, { encoding: 'utf-8' });
    fileIo.unlinkSync(path);
    const parsed: Object = JSON.parse(source);
    return validStopCommand(parsed) ? parsed as P2wlanVpnStopCommandV1 : null;
  } catch (_error) {
    try {
      fileIo.unlinkSync(path);
    } catch (_unlinkError) {
      // No stale stop command is accepted if cleanup fails.
    }
    return null;
  }
}

export function clearP2wlanVpnStopCommand(filesDir: string): void {
  const path = commandPath(filesDir);
  try {
    if (fileIo.accessSync(path, fileIo.AccessModeType.EXIST)) {
      fileIo.unlinkSync(path);
    }
  } catch (_error) {
    // The file is absent on a first launch. Treat that as already clear.
  }
}
