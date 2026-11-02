import { Want } from '@kit.AbilityKit';
import { vpnExtension } from '@kit.NetworkKit';
import {
  P2wlanVpnEngineSettingsV1,
  P2wlanVpnEngineSettingsSnapshotV1
} from './vpn_settings_snapshot';

export const P2WLAN_VPN_ABILITY_NAME: string = 'P2wlanVpnExtensionAbility';
export const P2WLAN_VPN_REQUEST_PARAMETER: string = 'p2wlanVpnStartV1';

const P2WLAN_BUNDLE_NAME: string = 'com.p2wlan.client';
const MAX_ENCODED_REQUEST_LENGTH: number = 4096;

export interface P2wlanVpnStartCommandV1 {
  version: number;
  requestId: string;
  settingsRevision: number;
}

export interface P2wlanVpnNetworkV1 {
  virtualIp: string;
  cidr: string;
}

interface VpnNetAddressV1 {
  address: string;
  family: number;
  port: number;
}

interface VpnLinkAddressV1 {
  address: VpnNetAddressV1;
  prefixLength: number;
}

interface VpnRouteConfigV1 {
  interface: string;
  destination: VpnLinkAddressV1;
  gateway: VpnNetAddressV1;
  hasGateway: boolean;
  isDefaultRoute: boolean;
}

interface P2wlanVpnConfigV1 {
  addresses: Array<VpnLinkAddressV1>;
  routes: Array<VpnRouteConfigV1>;
  dnsAddresses: Array<string>;
  isIPv4Accepted: boolean;
  isIPv6Accepted: boolean;
  isBlocking: boolean;
  mtu: number;
  vpnId?: string;
}

interface VpnAbilityRequestSuccessV1 {
  ok: true;
  phase: 'start_requested' | 'stop_requested';
}

interface VpnAbilityRequestFailureV1 {
  ok: false;
  error: VpnAbilityRequestErrorV1;
}

interface VpnAbilityRequestErrorV1 {
  code: 'INVALID_REQUEST' | 'VPN_ABILITY_REQUEST_FAILED';
}

interface ParsedIpv4CidrV1 {
  network: number;
  prefix: number;
}

export type VpnAbilityRequestResult =
  | VpnAbilityRequestSuccessV1
  | VpnAbilityRequestFailureV1;

export class P2wlanVpnRequestError extends Error {
  code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
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

function validRequest(request: P2wlanVpnStartCommandV1): boolean {
  return request != undefined && request.version == 1 &&
    typeof request.requestId == 'string' && request.requestId.length > 0 &&
    request.requestId.length <= 128 &&
    /^[A-Za-z0-9._:-]+$/.test(request.requestId) &&
    Number.isInteger(request.settingsRevision) &&
    request.settingsRevision > 0 &&
    request.settingsRevision <= 9007199254740991;
}

export function parseP2wlanVpnStartCommand(want: Want): P2wlanVpnStartCommandV1 {
  if (want.parameters == undefined) {
    throw new P2wlanVpnRequestError('INVALID_REQUEST');
  }
  const encoded = want.parameters[P2WLAN_VPN_REQUEST_PARAMETER];
  if (typeof encoded != 'string' || encoded.length == 0 ||
      encoded.length > MAX_ENCODED_REQUEST_LENGTH) {
    throw new P2wlanVpnRequestError('INVALID_REQUEST');
  }
  try {
    const parsed: Object = JSON.parse(encoded);
    if (!hasExactKeys(parsed, ['version', 'requestId', 'settingsRevision'])) {
      throw new P2wlanVpnRequestError('INVALID_REQUEST');
    }
    const command = parsed as P2wlanVpnStartCommandV1;
    if (!validRequest(command)) {
      throw new P2wlanVpnRequestError('INVALID_REQUEST');
    }
    return command;
  } catch {
    throw new P2wlanVpnRequestError('INVALID_REQUEST');
  }
}

function parseIpv4(address: string): number {
  const octets = address.split('.');
  if (octets.length != 4) {
    throw new P2wlanVpnRequestError('VPN_NETWORK_INVALID');
  }
  let value: number = 0;
  for (const octet of octets) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(octet) || Number(octet) > 255) {
      throw new P2wlanVpnRequestError('VPN_NETWORK_INVALID');
    }
    value = (value << 8) | Number(octet);
  }
  return value >>> 0;
}

function ipv4String(value: number): string {
  return `${(value >>> 24) & 255}.${(value >>> 16) & 255}.` +
    `${(value >>> 8) & 255}.${value & 255}`;
}

function parseCidr(cidr: string): ParsedIpv4CidrV1 {
  const parts = cidr.split('/');
  if (parts.length != 2 || !/^(0|[1-9][0-9]?)$/.test(parts[1])) {
    throw new P2wlanVpnRequestError('VPN_NETWORK_INVALID');
  }
  const prefix = Number(parts[1]);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new P2wlanVpnRequestError('VPN_NETWORK_INVALID');
  }
  const network = parseIpv4(parts[0]);
  const mask = prefix == 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  if (((network & mask) >>> 0) != network) {
    throw new P2wlanVpnRequestError('VPN_NETWORK_INVALID');
  }
  return { network: network, prefix: prefix };
}

function linkAddress(address: string, prefix: number): VpnLinkAddressV1 {
  return {
    address: { address: address, family: 1, port: 0 },
    prefixLength: prefix
  };
}

export function createVpnConfig(
  settings: P2wlanVpnEngineSettingsV1,
  network: P2wlanVpnNetworkV1
): P2wlanVpnConfigV1 {
  if (typeof network.virtualIp != 'string' || typeof network.cidr != 'string' ||
      !Number.isInteger(settings.mtu) || settings.mtu < 576 || settings.mtu > 1500) {
    throw new P2wlanVpnRequestError('VPN_NETWORK_INVALID');
  }
  const parsedCidr = parseCidr(network.cidr);
  const networkNumber = parsedCidr.network;
  const prefix = parsedCidr.prefix;
  const virtualIpNumber = parseIpv4(network.virtualIp);
  const mask = prefix == 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  if (((virtualIpNumber & mask) >>> 0) != networkNumber) {
    throw new P2wlanVpnRequestError('VPN_NETWORK_INVALID');
  }
  const routeAddress = ipv4String(networkNumber);
  const route: VpnRouteConfigV1 = {
    interface: '',
    destination: linkAddress(routeAddress, prefix),
    gateway: { address: '', family: 1, port: 0 },
    hasGateway: false,
    isDefaultRoute: prefix == 0
  };
  return {
    addresses: [linkAddress(network.virtualIp, prefix)],
    routes: [route],
    // DNS is intentionally empty: the current shared settings schema has no
    // DNS source, so the bridge must not invent a resolver.
    dnsAddresses: [],
    isIPv4Accepted: true,
    isIPv6Accepted: false,
    isBlocking: false,
    mtu: settings.mtu
  };
}

export function getConfiguredRouteSnapshot(config: P2wlanVpnConfigV1): Array<string> {
  const snapshot: Array<string> = [];
  for (const route of config.routes) {
    const destination = route.destination;
    const address = destination.address;
    if (typeof address.address != 'string' || address.family != 1 ||
        !Number.isInteger(destination.prefixLength)) {
      throw new P2wlanVpnRequestError('VPN_ROUTE_SNAPSHOT_INVALID');
    }
    snapshot.push(`${address.address}/${destination.prefixLength}`);
  }
  if (snapshot.length != 1) {
    throw new P2wlanVpnRequestError('VPN_ROUTE_SNAPSHOT_INVALID');
  }
  return snapshot;
}

export function buildP2wlanVpnWant(request: P2wlanVpnStartCommandV1): Want {
  if (!validRequest(request)) {
    throw new P2wlanVpnRequestError('INVALID_REQUEST');
  }
  const startWant: Want = {
    deviceId: '',
    bundleName: P2WLAN_BUNDLE_NAME,
    abilityName: P2WLAN_VPN_ABILITY_NAME,
    parameters: {
      p2wlanVpnStartV1: JSON.stringify(request)
    }
  };
  return startWant;
}

export function buildP2wlanVpnStopWant(): Want {
  const stopWant: Want = {
    deviceId: '',
    bundleName: P2WLAN_BUNDLE_NAME,
    abilityName: P2WLAN_VPN_ABILITY_NAME
  };
  return stopWant;
}

export async function requestP2wlanVpnStart(
  request: P2wlanVpnStartCommandV1
): Promise<VpnAbilityRequestResult> {
  if (!validRequest(request)) {
    return { ok: false, error: { code: 'INVALID_REQUEST' } };
  }
  try {
    await vpnExtension.startVpnExtensionAbility(buildP2wlanVpnWant(request));
    return { ok: true, phase: 'start_requested' };
  } catch (_error) {
    return { ok: false, error: { code: 'VPN_ABILITY_REQUEST_FAILED' } };
  }
}

export async function requestP2wlanVpnStop(): Promise<VpnAbilityRequestResult> {
  try {
    await vpnExtension.stopVpnExtensionAbility(buildP2wlanVpnStopWant());
    return { ok: true, phase: 'stop_requested' };
  } catch (_error) {
    return { ok: false, error: { code: 'VPN_ABILITY_REQUEST_FAILED' } };
  }
}
