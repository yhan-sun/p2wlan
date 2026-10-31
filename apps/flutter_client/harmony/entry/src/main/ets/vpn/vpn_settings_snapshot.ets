import { fileIo } from '@kit.CoreFileKit';

export const P2WLAN_VPN_SETTINGS_SNAPSHOT_SCHEMA_VERSION: number = 1;
export const P2WLAN_VPN_SETTINGS_SNAPSHOT_MAX_BYTES: number = 64 * 1024;
export const P2WLAN_VPN_SETTINGS_SNAPSHOT_FILE: string =
  'vpn-engine-settings-v1.json';

const SETTINGS_FIELDS: Array<string> = [
  'controlServer',
  'authToken',
  'networkId',
  'manualMode',
  'virtualIp',
  'deviceName',
  'overlayCidr',
  'tunInterface',
  'mtu',
  'udpBind',
  'udpAdvertise',
  'socketPool',
  'relayServers'
];

export interface P2wlanVpnEngineSettingsV1 {
  controlServer: string;
  authToken: string;
  networkId: string;
  manualMode: boolean;
  virtualIp: string;
  deviceName: string;
  overlayCidr: string;
  tunInterface: string;
  mtu: number;
  udpBind: string;
  udpAdvertise: string;
  socketPool: string;
  relayServers: Array<string>;
}

export interface P2wlanVpnEngineSettingsSnapshotV1 {
  schemaVersion: number;
  revision: number;
  settings: P2wlanVpnEngineSettingsV1;
}

export class P2wlanVpnSettingsSnapshotError extends Error {
  code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

export function parseP2wlanVpnEngineSettingsSnapshot(
  source: string
): P2wlanVpnEngineSettingsSnapshotV1 {
  try {
    const parsed: Object = JSON.parse(source);
    if (!hasExactKeys(parsed, ['schemaVersion', 'revision', 'settings'])) {
      throw new P2wlanVpnSettingsSnapshotError('VPN_ENGINE_SETTINGS_SNAPSHOT_INVALID');
    }
    const snapshot = parsed as P2wlanVpnEngineSettingsSnapshotV1;
    if (snapshot.schemaVersion != P2WLAN_VPN_SETTINGS_SNAPSHOT_SCHEMA_VERSION ||
        typeof snapshot.revision != 'number' || !Number.isInteger(snapshot.revision) ||
        snapshot.revision <= 0 || snapshot.revision > 9007199254740991 ||
        !isRecord(snapshot.settings as Object)) {
      throw new P2wlanVpnSettingsSnapshotError('VPN_ENGINE_SETTINGS_SNAPSHOT_INVALID');
    }
    snapshot.settings = validateSettings(snapshot.settings as Object);
    return snapshot;
  } catch (error) {
    if (error instanceof P2wlanVpnSettingsSnapshotError) {
      throw error;
    }
    throw new P2wlanVpnSettingsSnapshotError('VPN_ENGINE_SETTINGS_SNAPSHOT_INVALID');
  }
}

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

function validText(value: string, minLength: number, maxLength: number): boolean {
  return typeof value == 'string' && value.length >= minLength &&
    value.length <= maxLength && value.indexOf('\0') < 0 && value.trim() == value &&
    (minLength == 0 || value.trim().length > 0);
}

function validateSettings(value: Object): P2wlanVpnEngineSettingsV1 {
  if (!hasExactKeys(value, SETTINGS_FIELDS)) {
    throw new P2wlanVpnSettingsSnapshotError('VPN_ENGINE_SETTINGS_SNAPSHOT_INVALID');
  }
  const settings = value as P2wlanVpnEngineSettingsV1;
  if (!validText(settings.controlServer, 1, 2048) ||
      (!settings.controlServer.startsWith('https://') &&
       !settings.controlServer.startsWith('http://')) ||
      !validText(settings.authToken, 0, 8192) ||
      typeof settings.manualMode != 'boolean' ||
      !validText(settings.networkId, 1, 128) ||
      !validText(settings.virtualIp, 0, 64) ||
      !validText(settings.deviceName, 1, 128) ||
      !validText(settings.overlayCidr, 1, 64) ||
      !validText(settings.tunInterface, 1, 15) ||
      typeof settings.mtu != 'number' || !Number.isInteger(settings.mtu) ||
      settings.mtu < 576 || settings.mtu > 9000 ||
      !validText(settings.udpBind, 1, 128) ||
      !validText(settings.udpAdvertise, 0, 128) ||
      typeof settings.socketPool != 'string' ||
      (settings.socketPool != 'off' && settings.socketPool != '2' &&
       settings.socketPool != '3' && settings.socketPool != '4') ||
      !Array.isArray(settings.relayServers) || settings.relayServers.length > 64) {
    throw new P2wlanVpnSettingsSnapshotError('VPN_ENGINE_SETTINGS_SNAPSHOT_INVALID');
  }
  if (settings.manualMode) {
    if (settings.authToken.length != 0) {
      throw new P2wlanVpnSettingsSnapshotError('VPN_ENGINE_SETTINGS_SNAPSHOT_INVALID');
    }
  } else if (settings.authToken.trim().length == 0) {
    throw new P2wlanVpnSettingsSnapshotError('VPN_ENGINE_SETTINGS_TOKEN_MISSING');
  }
  for (const relayServer of settings.relayServers) {
    if (!validText(relayServer, 1, 2048)) {
      throw new P2wlanVpnSettingsSnapshotError('VPN_ENGINE_SETTINGS_SNAPSHOT_INVALID');
    }
  }
  return settings;
}

/** Reads one bounded, app-private snapshot from the VPN extension context. */
export function readP2wlanVpnEngineSettingsSnapshot(
  filesDir: string
): P2wlanVpnEngineSettingsSnapshotV1 {
  if (!validText(filesDir, 1, 4096)) {
    throw new P2wlanVpnSettingsSnapshotError('VPN_ENGINE_SETTINGS_SNAPSHOT_READ_FAILED');
  }
  const snapshotPath = `${filesDir}/p2wlan/${P2WLAN_VPN_SETTINGS_SNAPSHOT_FILE}`;
  let source: string;
  try {
    const stat = fileIo.statSync(snapshotPath);
    if (!Number.isInteger(stat.size) || stat.size <= 0) {
      throw new P2wlanVpnSettingsSnapshotError('VPN_ENGINE_SETTINGS_SNAPSHOT_INVALID');
    }
    if (stat.size > P2WLAN_VPN_SETTINGS_SNAPSHOT_MAX_BYTES) {
      throw new P2wlanVpnSettingsSnapshotError('VPN_ENGINE_SETTINGS_SNAPSHOT_TOO_LARGE');
    }
    source = fileIo.readTextSync(snapshotPath, { encoding: 'utf-8' });
  } catch (error) {
    if (error instanceof P2wlanVpnSettingsSnapshotError) {
      throw error;
    }
    throw new P2wlanVpnSettingsSnapshotError('VPN_ENGINE_SETTINGS_SNAPSHOT_READ_FAILED');
  }

  return parseP2wlanVpnEngineSettingsSnapshot(source);
}
