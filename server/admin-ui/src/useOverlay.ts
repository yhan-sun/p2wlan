import { useEffect, useRef } from 'react'

interface OverlayEntry {
  close: () => void
  lockScroll: boolean
}

const overlays: OverlayEntry[] = []
let savedOverflow: { value: string; priority: string } | undefined

function updateScrollLock() {
  const needsLock = overlays.some((overlay) => overlay.lockScroll)
  if (needsLock && !savedOverflow) {
    savedOverflow = {
      value: document.body.style.getPropertyValue('overflow'),
      priority: document.body.style.getPropertyPriority('overflow'),
    }
    document.body.style.setProperty('overflow', 'hidden')
  } else if (!needsLock && savedOverflow) {
    if (savedOverflow.value) {
      document.body.style.setProperty('overflow', savedOverflow.value, savedOverflow.priority)
    } else {
      document.body.style.removeProperty('overflow')
    }
    savedOverflow = undefined
  }
}

function closeTopOverlay(event: KeyboardEvent) {
  if (event.key !== 'Escape' || event.isComposing || event.repeat) return
  const overlay = overlays[overlays.length - 1]
  if (!overlay) return
  event.preventDefault()
  event.stopImmediatePropagation()
  overlay.close()
}

/** Share Escape handling and scroll ownership across fullscreen views and dialogs. */
export function useOverlay(active: boolean, onClose: () => void, options: { lockScroll?: boolean } = {}) {
  const close = useRef(onClose)
  close.current = onClose
  const lockScroll = options.lockScroll ?? true

  useEffect(() => {
    if (!active) return
    const overlay: OverlayEntry = { close: () => close.current(), lockScroll }
    if (overlays.length === 0) window.addEventListener('keydown', closeTopOverlay, true)
    overlays.push(overlay)
    updateScrollLock()
    return () => {
      const index = overlays.indexOf(overlay)
      if (index !== -1) overlays.splice(index, 1)
      updateScrollLock()
      if (overlays.length === 0) window.removeEventListener('keydown', closeTopOverlay, true)
    }
  }, [active, lockScroll])
}
