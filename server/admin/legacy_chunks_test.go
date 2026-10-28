package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLegacyChunksReloadTheDocumentWithoutLoadingNewDependencies(t *testing.T) {
	for _, name := range []string{"ConnectionWorkspace", "ConnectionTopology", "TopologyCanvas", "TopologyViewport"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			recorder := httptest.NewRecorder()
			if !serveLegacyChunkUpgrade(recorder, httptest.NewRequest(method, "/admin/"+name+".js", nil), name+".js") {
				t.Fatalf("legacy %s was not handled", name)
			}
			if recorder.Code != http.StatusOK || !strings.Contains(recorder.Header().Get("Content-Type"), "javascript") {
				t.Fatalf("%s %s: %d %v", method, name, recorder.Code, recorder.Header())
			}
			body := recorder.Body.String()
			if method == http.MethodHead {
				if body != "" {
					t.Fatal("HEAD returned a bridge body")
				}
				continue
			}
			for _, required := range []string{"window.location.reload()", "sessionStorage", "export function " + name} {
				if !strings.Contains(body, required) {
					t.Fatalf("%s bridge missing %s", name, required)
				}
			}
			if strings.Contains(body, "import ") || strings.Contains(body, "location.href=") {
				t.Fatal("bridge must preserve the URL and avoid mixed-version imports")
			}
		}
	}
	if serveLegacyChunkUpgrade(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/admin/unknown.js", nil), "unknown.js") {
		t.Fatal("unknown missing assets must remain 404")
	}
}
