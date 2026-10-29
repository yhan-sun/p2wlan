import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import test from 'node:test'
import { build } from 'esbuild'
import ts from 'typescript'

const built = await build({ entryPoints: ['src/i18n.ts'], bundle: true, platform: 'node', format: 'cjs', write: false })
const module = { exports: {} }
new Function('module', 'exports', 'require', built.outputFiles[0].text)(module, module.exports, createRequire(import.meta.url))
const { setLocale, tr } = module.exports

test('all literal relationship-page labels and state messages have English translations', () => {
  setLocale('en-US')
  const keys = new Set()
  for (const filename of ['src/features/relationships/RelationshipsPage.tsx', 'src/features/relationships/TopologyCanvas.tsx', 'src/refresh.tsx']) {
    const source = ts.createSourceFile(filename, readFileSync(filename, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
    const collect = (node) => {
      if (ts.isStringLiteral(node) && /\p{Script=Han}/u.test(node.text)) keys.add(node.text)
      ts.forEachChild(node, collect)
    }
    const visit = (node) => {
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'tr') {
        node.arguments.forEach(collect)
      }
      ts.forEachChild(node, visit)
    }
    visit(source)
  }
  assert.ok(keys.size > 70)
  assert.deepEqual([...keys].filter((key) => /\p{Script=Han}/u.test(tr(key))), [], 'Missing English translations')
  setLocale('zh-CN')
})

test('connection task flow and diagnostic disclosures have English translations', () => {
  setLocale('en-US')
  const keys = new Set()
  for (const filename of ['ConnectionWorkspace', 'ConnectionsPage', 'ConnectionTopology', 'ConnectionDrawer']) {
    const source = ts.createSourceFile(filename, readFileSync(`src/features/connections/${filename}.tsx`, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX)
    const collect = (node) => {
      if (ts.isStringLiteral(node) && /\p{Script=Han}/u.test(node.text)) keys.add(node.text)
      ts.forEachChild(node, collect)
    }
    const visit = (node) => {
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'tr') node.arguments.forEach(collect)
      ts.forEachChild(node, visit)
    }
    visit(source)
  }
  assert.ok(keys.size > 70)
  assert.deepEqual([...keys].filter((key) => /\p{Script=Han}/u.test(tr(key))), [], 'Missing English connection labels')
  setLocale('zh-CN')
})
