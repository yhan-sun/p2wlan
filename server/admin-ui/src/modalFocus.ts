const focusableSelector = 'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

function focusableElements(surface: HTMLElement): HTMLElement[] {
  return [...surface.querySelectorAll<HTMLElement>(focusableSelector)]
    .filter((element) => element.tabIndex >= 0 && !element.closest('[hidden], [inert]') && element.getClientRects().length > 0)
}

/** Limit interaction to an existing fullscreen surface without rebuilding its graph. */
export function activateModalSurface(surface: HTMLElement) {
  const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null
  const background = new Map<HTMLElement, boolean>()
  const isolateBackground = () => {
    const current = new Set<HTMLElement>()
    let branch: HTMLElement = surface
    while (branch.parentElement) {
      for (const sibling of branch.parentElement.children) {
        // Native details dialogs live in a body portal and own their own modal
        // layer. Making that portal inert would hide its contents from AT.
        if (sibling === branch || !(sibling instanceof HTMLElement) || sibling.tagName === 'DIALOG') continue
        current.add(sibling)
        if (!background.has(sibling)) background.set(sibling, sibling.inert)
        sibling.inert = true
      }
      if (branch.parentElement === document.body) break
      branch = branch.parentElement
    }
    for (const [element, inert] of background) {
      if (current.has(element)) continue
      element.inert = inert
      background.delete(element)
    }
  }
  const focusInside = () => (surface.querySelector<HTMLElement>('[data-fullscreen-toggle]') ?? focusableElements(surface)[0] ?? surface).focus({ preventScroll: true })
  // A native connection-details dialog can open above this surface. Its browser
  // focus trap owns the top layer until it closes, then focus returns here.
  const nativeDialogOwnsFocus = () => {
    const active = document.activeElement
    return active instanceof HTMLElement && !surface.contains(active) && Boolean(active.closest('dialog[open]'))
  }
  const containFocus = () => {
    if (surface.isConnected && !surface.contains(document.activeElement) && !nativeDialogOwnsFocus()) focusInside()
  }
  const trapTab = (event: KeyboardEvent) => {
    if (event.key !== 'Tab' || nativeDialogOwnsFocus()) return
    const elements = focusableElements(surface)
    const first = elements[0]
    const last = elements.at(-1)
    if (!first || document.activeElement === surface || !surface.contains(document.activeElement) || event.shiftKey && document.activeElement === first || !event.shiftKey && document.activeElement === last) {
      event.preventDefault()
      const target = event.shiftKey ? last : first
      target?.focus({ preventScroll: true })
      if (!first) surface.focus({ preventScroll: true })
    }
  }
  // Selection can insert new background siblings while fullscreen remains
  // mounted. Native dialog close/removal may move focus to body without a
  // focusin event, so reconcile focus at the same DOM lifecycle boundary.
  const observer = new MutationObserver(() => {
    if (!surface.isConnected) return
    isolateBackground()
    containFocus()
  })
  observer.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['open'] })
  document.addEventListener('focusin', containFocus)
  document.addEventListener('keydown', trapTab, { capture: true })
  isolateBackground()
  focusInside()
  return () => {
    observer.disconnect()
    document.removeEventListener('focusin', containFocus)
    document.removeEventListener('keydown', trapTab, { capture: true })
    for (const [element, inert] of background) element.inert = inert
    if (previous?.isConnected && !previous.closest('[inert]')) previous.focus({ preventScroll: true })
  }
}
