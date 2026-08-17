// ============================================================================
// FROZEN — 2026-08-17 (see docs/adr/0004-remove-react-unify-flutter.md)
// This React web console is being removed in favor of the Flutter client.
// DO NOT add features, pages, or capabilities here. The only permitted
// changes are (a) bug fixes that block removal, or (b) migration work
// explicitly scoped by ADR 0004. All new user-facing work goes to
// apps/flutter_client. Frozen at baseline commit 7bc88c8.
// ============================================================================
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
