// Execute the actual ArkTS extension with controlled SDK/native boundaries.
// These tests establish ordering and fencing, not a real VPN fd or device run.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const ts = require(process.env.P2WLAN_TYPESCRIPT_MODULE || 'typescript');

const filename = path.resolve(__dirname,
  '../../harmony/entry/src/main/ets/vpn/P2wlanVpnExtensionAbility.ets');
const source = ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  fileName: 'P2wlanVpnExtensionAbility.ts',
}).outputText;

class CodedError extends Error {
  constructor(code) { super(code); this.code = code; }
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

function fixture(pausedPhase) {
  const entered = deferred();
  const released = deferred();
  const events = [];
  const snapshots = [];
  const timers = new Map();
  let settingsRevision = 7;
  let nativeStatus = { status: 'ready' };
  let stopResult = { status: 'stopped' };
  let statusError = false;
  const phase = async (name, result) => {
    events.push(name);
    if (pausedPhase === name) {
      entered.resolve();
      await released.promise;
    }
    return result;
  };
  const native = {
    prepareVpnNetworkV1: () => phase('prepare', {
      status: 'ready', virtualIp: '10.20.0.2', cidr: '10.20.0.0/16',
    }),
    discardVpnNetworkV1: () => { events.push('discard'); return true; },
    startVpnEngineV1: () => phase('start', { status: 'ready' }),
    stopVpnEngineV1: () => phase('stop', stopResult),
    stopVpnEngineForExtensionDestroyV1: (identity, timeout) => {
      assert.equal(identity.instanceId, 'vpn-a');
      assert.equal(identity.generation, 1);
      assert.ok(timeout > 0 && timeout <= 3000);
      events.push('bounded-stop');
      return stopResult;
    },
    getVpnEngineStatusV1: (identity) => {
      assert.equal(identity.instanceId, 'vpn-a');
      assert.equal(identity.generation, 1);
      events.push('status');
      if (statusError) throw new Error('native query unavailable');
      return nativeStatus;
    },
  };
  const connection = {
    generateVpnId: () => phase('id', 'vpn-a'),
    protectProcessNet: () => phase('protect'),
    create: () => phase('create', 42),
    destroy: () => phase('destroy'),
  };
  const publish = (_dir, requestId, operation, revision, status, identity, code) => {
    snapshots.push({ requestId, operation, settingsRevision: revision, status, identity, code });
  };
  const modules = {
    '@kit.AbilityKit': {},
    '@kit.ArkTS': { util: { generateRandomUUID: () => 'vpn-a' } },
    '@kit.NetworkKit': {
      vpnExtension: { createVpnConnection: () => connection },
      VpnExtensionAbility: class { context = { filesDir: '/app-private' }; },
    },
    './vpn_request': {
      parseP2wlanVpnStartCommand: () => ({ requestId: 'request-a', settingsRevision: 7 }),
      createVpnConfig: () => ({}),
      getConfiguredRouteSnapshot: () => ['10.20.0.0/16'],
      P2wlanVpnRequestError: CodedError,
    },
    './vpn_lifecycle_command': { consumeP2wlanVpnStopCommand: () => null },
    './vpn_settings_snapshot': {
      P2wlanVpnSettingsSnapshotError: CodedError,
      readP2wlanVpnEngineSettingsSnapshot: () => ({
        revision: settingsRevision,
        settings: { manualMode: false, udpAdvertise: '', relayServers: [] },
      }),
    },
    './vpn_engine_status_snapshot': {
      publishP2wlanVpnEngineStatusSnapshot: publish,
      readP2wlanVpnEngineStatusSnapshot: () => snapshots.at(-1),
      P2wlanVpnEngineStatusSnapshotError: CodedError,
    },
    './native_vpn_engine': {
      loadNativeVpnEngineV1: async () => native,
      isNativeVpnStopped: (result) => result?.status === 'stopped',
      NativeVpnAdapterError: CodedError,
    },
  };
  const exports = {};
  vm.runInNewContext(source, {
    exports, Error, console: { info() {} },
    require(name) {
      assert.ok(Object.hasOwn(modules, name), `Unexpected import ${name}`);
      return modules[name];
    },
    setInterval(callback) { timers.set(1, callback); return 1; },
    clearInterval(id) { timers.delete(id); },
  }, { filename });
  const extension = new exports.default();
  return {
    extension, events, snapshots, entered: entered.promise,
    release: released.resolve,
    changeSettings: () => { settingsRevision++; },
    failNative: () => { nativeStatus = { status: 'failed', code: 'auth_failed' }; },
    loseNativeStatus: () => { statusError = true; },
    drainNative: () => { stopResult = { status: 'draining', code: 'stop_timeout' }; },
    heartbeat: () => { assert.ok(timers.has(1)); timers.get(1)(); },
  };
}

async function settle() {
  // Flush promise chains and any async cleanup without timing guesses.
  for (let turn = 0; turn < 8; turn++) {
    await new Promise(setImmediate);
  }
}

test('unchanged settings start and heartbeat retain the exact live native identity', async () => {
  const f = fixture();
  f.extension.onCreate({});
  await settle();
  assert.equal(f.snapshots.at(-1).status, 'ready');
  f.heartbeat();
  assert.ok(f.events.includes('status'));
  assert.equal(f.snapshots.at(-1).status, 'ready');
  assert.ok(!f.events.includes('destroy'));
  f.extension.onDestroy();
  await settle();
  assert.equal(f.snapshots.at(-1).status, 'stopped');
  assert.ok(f.events.indexOf('bounded-stop') < f.events.indexOf('destroy'));
});

for (const [pausedPhase, forbidden] of [['protect', 'prepare'], ['create', 'start']]) {
  test(`settings changed during ${pausedPhase} cannot enter ${forbidden}`, async () => {
    const f = fixture(pausedPhase);
    f.extension.onCreate({});
    await f.entered;
    f.changeSettings();
    f.release();
    await settle();
    assert.ok(!f.events.includes(forbidden));
    assert.ok(f.snapshots.some((s) => s.code === 'VPN_ENGINE_SETTINGS_SNAPSHOT_STALE'));
    assert.equal(f.snapshots.at(-1).status, 'failed');
    if (pausedPhase === 'create') {
      assert.ok(f.events.includes('destroy'));
      assert.ok(f.events.includes('discard'));
    }
  });
}

test('settings changed during native start stop that owner before destroying the VPN', async () => {
  const f = fixture('start');
  f.extension.onCreate({});
  await f.entered;
  f.changeSettings();
  f.release();
  await settle();
  assert.ok(!f.snapshots.some((s) => s.status === 'ready'));
  assert.ok(f.events.includes('stop'));
  assert.ok(f.events.indexOf('stop') < f.events.indexOf('destroy'));
  assert.equal(f.snapshots.at(-1).status, 'failed');
});

test('native failure ends the ready heartbeat and drains before system destruction', async () => {
  const f = fixture();
  f.extension.onCreate({});
  await settle();
  const before = f.snapshots.length;
  f.failNative();
  f.heartbeat();
  await settle();
  assert.ok(!f.snapshots.slice(before).some((s) => s.status === 'ready'));
  assert.ok(f.snapshots.slice(before).some((s) => s.code === 'auth_failed'));
  assert.ok(f.events.indexOf('bounded-stop') < f.events.indexOf('destroy'));
  assert.equal(f.snapshots.at(-1).status, 'failed');
});

test('unconfirmed native stop keeps the system VPN owned and never refreshes ready', async () => {
  const f = fixture();
  f.extension.onCreate({});
  await settle();
  const before = f.snapshots.length;
  f.failNative();
  f.drainNative();
  f.heartbeat();
  await settle();
  assert.equal(f.snapshots.at(-1).status, 'draining');
  assert.ok(!f.snapshots.slice(before).some((s) => s.status === 'ready'));
  assert.ok(!f.events.includes('destroy'));
});

test('a native status query failure cannot refresh ready or invent a completed stop', async () => {
  const f = fixture();
  f.extension.onCreate({});
  await settle();
  const before = f.snapshots.length;
  f.loseNativeStatus();
  f.drainNative();
  f.heartbeat();
  await settle();
  assert.equal(f.snapshots.at(-1).status, 'draining');
  assert.ok(!f.snapshots.slice(before).some((s) => s.status === 'ready'));
  assert.ok(!f.events.includes('destroy'));
});
