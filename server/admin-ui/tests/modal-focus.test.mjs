import assert from 'node:assert/strict'
import test from 'node:test'
import { activateModalSurface } from '../src/modalFocus.ts'

function setup(t) {
  const originals = new Map(['document', 'HTMLElement', 'MutationObserver'].map((key) => [key, Object.getOwnPropertyDescriptor(globalThis, key)]))
  const document = new EventTarget()
  const observers = new Set()
  class MutationObserver {
    constructor(callback) { this.callback = callback }
    observe(target, options) {
      assert.equal(target, document.body)
      assert.deepEqual(options, { childList: true, subtree: true, attributes: true, attributeFilter: ['open'] })
      observers.add(this)
    }
    disconnect() { observers.delete(this) }
  }
  const flushMutations = () => { for (const observer of observers) observer.callback() }
  class Element extends EventTarget {
    tagName = 'DIV'
    children = []
    parentElement = null
    inert = false
    hidden = false
    tabIndex = -1
    isConnected = true
    dialog = false
    toggle = false
    append(...elements) { for (const element of elements) { this.children.push(element); element.parentElement = this; element.isConnected = true } }
    remove() {
      this.parentElement.children = this.parentElement.children.filter((element) => element !== this)
      this.parentElement = null
      this.isConnected = false
    }
    focus() { document.activeElement = this; document.dispatchEvent(new Event('focusin')) }
    contains(element) { return this === element || this.children.some((child) => child.contains(element)) }
    querySelectorAll() { return this.children.flatMap((child) => [child, ...child.querySelectorAll()]) }
    querySelector() { return this.querySelectorAll().find((child) => child.toggle) }
    getClientRects() { return this.hidden ? [] : [{}] }
    closest(selector) {
      if (selector === 'dialog[open]' ? this.dialog : this.inert || this.hidden) return this
      return this.parentElement?.closest(selector) ?? null
    }
  }
  const body = new Element()
  const page = new Element()
  const surface = new Element()
  const before = new Element()
  const after = new Element()
  const sidebar = new Element()
  const preservedInert = new Element()
  preservedInert.inert = true
  const first = new Element()
  const toggle = new Element()
  const last = new Element()
  const excluded = new Element()
  excluded.hidden = true
  first.tabIndex = toggle.tabIndex = last.tabIndex = excluded.tabIndex = before.tabIndex = 0
  toggle.toggle = true
  surface.append(first, toggle, last, excluded)
  page.append(before, surface, after)
  body.append(sidebar, page, preservedInert)
  document.body = body
  document.activeElement = before
  Object.defineProperty(globalThis, 'document', { configurable: true, value: document })
  Object.defineProperty(globalThis, 'HTMLElement', { configurable: true, value: Element })
  Object.defineProperty(globalThis, 'MutationObserver', { configurable: true, value: MutationObserver })
  t.after(() => {
    for (const [key, descriptor] of originals) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor)
      else Reflect.deleteProperty(globalThis, key)
    }
  })
  const tab = (shiftKey = false) => {
    const event = new Event('keydown', { cancelable: true })
    Object.assign(event, { key: 'Tab', shiftKey })
    document.dispatchEvent(event)
    return event
  }
  return { document, body, page, surface, before, after, sidebar, preservedInert, first, toggle, last, tab, Element, observers, flushMutations }
}

test('fullscreen contains focus, isolates every background branch and restores its trigger and inert states', (t) => {
  const dom = setup(t)
  const release = activateModalSurface(dom.surface)
  assert.equal(dom.document.activeElement, dom.toggle)
  for (const element of [dom.before, dom.after, dom.sidebar, dom.preservedInert]) assert.equal(element.inert, true)
  assert.equal(dom.surface.inert, false)
  dom.last.focus()
  assert.equal(dom.tab().defaultPrevented, true)
  assert.equal(dom.document.activeElement, dom.first)
  assert.equal(dom.tab(true).defaultPrevented, true)
  assert.equal(dom.document.activeElement, dom.last)
  dom.before.focus()
  assert.equal(dom.document.activeElement, dom.toggle)
  release()
  assert.equal(dom.document.activeElement, dom.before)
  for (const element of [dom.before, dom.after, dom.sidebar]) assert.equal(element.inert, false)
  assert.equal(dom.preservedInert.inert, true)
  dom.last.focus()
  assert.equal(dom.tab().defaultPrevented, false)
})

test('a native details dialog above fullscreen retains ownership until it closes', (t) => {
  const dom = setup(t)
  const release = activateModalSurface(dom.surface)
  const dialog = new dom.Element()
  dialog.tagName = 'DIALOG'
  dialog.dialog = true
  const close = new dom.Element()
  close.tabIndex = 0
  dialog.append(close)
  dom.body.append(dialog)
  close.focus()
  assert.equal(dom.document.activeElement, close)
  assert.equal(dom.tab().defaultPrevented, false)
  dialog.dialog = false
  dom.document.dispatchEvent(new Event('focusin'))
  assert.equal(dom.document.activeElement, dom.toggle)
  release()
})

test('background siblings added during fullscreen become inert and release their original state when moved away', (t) => {
  const dom = setup(t)
  const release = activateModalSurface(dom.surface)
  const selectionNote = new dom.Element()
  dom.page.append(selectionNote)
  dom.flushMutations()
  assert.equal(selectionNote.inert, true)
  assert.equal(dom.document.activeElement, dom.toggle)
  selectionNote.remove()
  dom.surface.append(selectionNote)
  dom.flushMutations()
  assert.equal(selectionNote.inert, false)
  const persistentNote = new dom.Element()
  dom.page.append(persistentNote)
  dom.flushMutations()
  assert.equal(persistentNote.inert, true)
  release()
  assert.equal(persistentNote.inert, false)
  assert.equal(dom.observers.size, 0)
  const afterRelease = new dom.Element()
  dom.page.append(afterRelease)
  dom.flushMutations()
  assert.equal(afterRelease.inert, false)
})

test('native dialog portals remain usable and closing or removing one restores lost fullscreen focus without focusin', (t) => {
  const dom = setup(t)
  const release = activateModalSurface(dom.surface)
  const dialog = new dom.Element()
  dialog.tagName = 'DIALOG'
  dialog.dialog = true
  const close = new dom.Element()
  close.tabIndex = 0
  dialog.append(close)
  dom.body.append(dialog)
  close.focus()
  dom.flushMutations()
  assert.equal(dialog.inert, false)
  assert.equal(dom.document.activeElement, close)
  dialog.dialog = false
  dom.document.activeElement = dom.body
  dom.flushMutations()
  assert.equal(dom.document.activeElement, dom.toggle)
  dialog.dialog = true
  close.focus()
  dialog.remove()
  dom.document.activeElement = dom.body
  dom.flushMutations()
  assert.equal(dom.document.activeElement, dom.toggle)
  // A Tab immediately after native close is contained before observer delivery.
  dom.document.activeElement = dom.body
  assert.equal(dom.tab().defaultPrevented, true)
  assert.equal(dom.document.activeElement, dom.first)
  release()
})
