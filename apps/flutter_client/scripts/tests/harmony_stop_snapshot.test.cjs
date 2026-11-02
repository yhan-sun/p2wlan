// Host regression for ArkTS stop handoff. Set P2WLAN_TYPESCRIPT_MODULE to an
// installed TypeScript module when it is not available through Node resolution.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const ts = require(process.env.P2WLAN_TYPESCRIPT_MODULE || 'typescript');

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'harmony-stop-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const fileIo = {
    AccessModeType: { EXIST: 0 },
    OpenMode: { WRITE_ONLY: fs.constants.O_WRONLY, CREATE: fs.constants.O_CREAT,
      TRUNC: fs.constants.O_TRUNC, NOFOLLOW: fs.constants.O_NOFOLLOW },
    accessSync: fs.existsSync,
    statSync: fs.statSync,
    readTextSync: (file) => fs.readFileSync(file, 'utf8'),
    mkdirSync: (file, recursive) => fs.mkdirSync(file, { recursive }),
    openSync: (file, flags) => ({ fd: fs.openSync(file, flags) }),
    writeSync: (fd, buffer, options) => fs.writeSync(
      fd, Buffer.from(buffer), options.offset, options.length, options.offset),
    fsyncSync: fs.fsyncSync,
    closeSync: fs.closeSync,
    renameSync: fs.renameSync,
    unlinkSync: fs.unlinkSync,
  };
  const filename = path.resolve(__dirname,
    '../../harmony/entry/src/main/ets/vpn/vpn_engine_status_snapshot.ets');
  const source = ts.transpileModule(fs.readFileSync(filename, 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
    fileName: 'vpn_engine_status_snapshot.ts',
  }).outputText;
  const exports = {};
  vm.runInNewContext(source, {
    exports, setTimeout, require: (name) => {
      if (name === '@kit.CoreFileKit') return { fileIo };
      if (name === '@kit.ArkTS') return {
        util: { TextEncoder: { create: () => ({
          encodeInto: (text) => new TextEncoder().encode(text),
        }) } },
      };
      throw new Error(`Unexpected SDK import: ${name}`);
    },
  }, { filename });
  const identity = { instanceId: 'instance-a', generation: 1 };
  const publish = (request, operation, status, code, settingsRevision = 7) =>
    exports.publishP2wlanVpnEngineStatusSnapshot(directory, request, operation,
      settingsRevision, status, identity, code, true);
  publish('start-a', 'start', 'ready');
  const wait = (timeout = 1000) => exports.waitForAndFinalizeP2wlanVpnEngineStopSnapshot(
    directory, 'stop-a', 7, timeout, { requestId: 'start-a', afterStatusRevision: 1 });
  return { publish, wait };
}

test('waits for delayed onDestroy handoff and native stop before finalizing', async (t) => {
  const { publish, wait } = fixture(t);
  const pending = wait();
  publish('stop-a', 'stop', 'stopping', 'ENGINE_STOP_REQUESTED');
  const timer = setTimeout(() =>
    publish('stop-a', 'stop', 'stopping', 'ENGINE_NATIVE_STOPPED'), 150);
  t.after(() => clearTimeout(timer));
  const result = await pending;
  assert.equal(result.status, 'stopped');
  assert.equal(result.code, 'ENGINE_STOPPED');
  assert.equal(result.requestId, 'stop-a');
});

test('rejects a replacement session while waiting for handoff', async (t) => {
  const { publish, wait } = fixture(t);
  const pending = wait();
  publish('start-b', 'start', 'ready');
  await assert.rejects(pending, { code: 'VPN_ENGINE_STATUS_SNAPSHOT_STALE' });
});

test('rejects a settings revision change while waiting', async (t) => {
  const { publish, wait } = fixture(t);
  const pending = wait();
  publish('start-a', 'start', 'ready', undefined, 8);
  await assert.rejects(pending, { code: 'VPN_ENGINE_STATUS_SNAPSHOT_STALE' });
});

test('times out without inventing a successful stop', async (t) => {
  const { wait } = fixture(t);
  await assert.rejects(wait(50), { code: 'VPN_ENGINE_STATUS_STOP_NOT_CONFIRMED' });
});

test('keeps draining as an unconfirmed stop', async (t) => {
  const { publish, wait } = fixture(t);
  const pending = wait();
  publish('stop-a', 'stop', 'draining', 'ENGINE_STOP_DRAINING');
  await assert.rejects(pending, { code: 'VPN_ENGINE_STATUS_STOP_NOT_CONFIRMED' });
});
