package admin

import (
	"fmt"
	"net/http"
	"strconv"
)

// Tabs opened before content-hashed bundles were introduced still request
// these fixed lazy-chunk names. Never give them a new chunk linked against an
// incompatible, already-loaded entry module. A dependency-free bridge reloads
// the no-store document once; later hashed deployments recover in the client.
func serveLegacyChunkUpgrade(w http.ResponseWriter, r *http.Request, asset string) bool {
	var export string
	switch asset {
	case "ConnectionWorkspace.js":
		export = "ConnectionWorkspace"
	case "ConnectionTopology.js":
		export = "ConnectionTopology"
	case "TopologyCanvas.js":
		export = "TopologyCanvas"
	case "TopologyViewport.js":
		export = "TopologyViewport"
	default:
		return false
	}
	// Keep the token and route untouched. If storage is blocked, or a reload
	// was already attempted in the last minute, the old error boundary offers
	// its existing explicit reload action instead of creating a reload loop.
	body := fmt.Sprintf(`const key="p2wlan-admin-asset-recovery";
try {
  const now=Date.now();
  const previous=Number(sessionStorage.getItem(key)||0);
  if (navigator.onLine && (!Number.isFinite(previous)||previous<=0||now<previous||now-previous>=60000)) {
    sessionStorage.setItem(key,String(now));
    window.location.reload();
  }
} catch {}
export function %s() { return null; }
throw new Error("The admin console was updated. Reload this page.");
`, export)
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(body))
	}
	return true
}
