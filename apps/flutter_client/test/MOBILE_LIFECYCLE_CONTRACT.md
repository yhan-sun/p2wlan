# Mobile Lifecycle Event-Loop Contract

The Flutter status event loop is scoped to an app-foreground and physical-network epoch.

- Entering a non-resumed lifecycle state invalidates the current diagnostics long poll and immediately releases the event-loop slot.
- A late response from the suspended epoch is generation-fenced and cannot mutate the resumed snapshot or start another loop.
- Returning to `resumed` refreshes daemon process identity and path state before creating a new long poll.
- Low-frequency background status polling remains separate from the foreground event stream.

This deterministic contract does not replace physical Android/iOS validation for Doze, OEM background restrictions, or Wi-Fi/cellular handoff latency.
