import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { lifecycleLabel, transitionReasonLabel, transitionReasonLabels } from '../src/connectionLabels.ts'

test('every backend transition reason has Chinese and English labels', () => {
  const backend = readFileSync(new URL('../../database/path_telemetry.go', import.meta.url), 'utf8')
  const reasonBlock = backend.match(/var validTransitionReasons = map\[string\]struct\{\}\{([\s\S]*?)\n\}/)?.[1]
  assert.ok(reasonBlock, 'could not find the backend transition reason contract')
  const reasons = [...reasonBlock.matchAll(/"([a-z_]+)"/g)].map((match) => match[1])
  assert.equal(reasons.length, 23)
  assert.deepEqual(Object.keys(transitionReasonLabels).sort(), [...reasons, 'unknown'].sort())
  for (const reason of reasons) {
    const chinese = transitionReasonLabel(reason, 'zh-CN')
    const english = transitionReasonLabel(reason, 'en-US')
    assert.match(chinese, /[\u4e00-\u9fff]/, reason)
    assert.doesNotMatch(english, /[\u4e00-\u9fff]/, reason)
    assert.notEqual(chinese, '未知原因', reason)
    assert.notEqual(english, 'Unknown reason', reason)
  }
})

test('unknown transition reasons retain a localized visible label', () => {
  assert.equal(transitionReasonLabel('future_reason', 'zh-CN'), '未知原因')
  assert.equal(transitionReasonLabel('future_reason', 'en-US'), 'Unknown reason')
  assert.equal(transitionReasonLabel('', 'en-US'), '—')
})

test('all accepted lifecycle states are localized', () => {
  assert.equal(lifecycleLabel('online', 'zh-CN'), '在线')
  assert.equal(lifecycleLabel('offline', 'en-US'), 'Offline')
  assert.equal(lifecycleLabel('unbound', 'zh-CN'), '未绑定')
  assert.equal(lifecycleLabel('unbound', 'en-US'), 'Unbound')
  assert.equal(lifecycleLabel('future', 'zh-CN'), '未知')
})
