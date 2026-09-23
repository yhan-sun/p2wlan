package api

import (
	"strings"
	"testing"
)

func TestHardHardA0SessionTagsAreStableAndRedacted(t *testing.T) {
	const token = "a01face0-1234abcd"
	role, sessionTag, planTag, ok := hardHardA0SessionTags("hh1:i:" + token + ":1:2:3:4")
	if !ok {
		t.Fatal("valid Hard-Hard session envelope was rejected")
	}
	if role != "initiator" || sessionTag != "a8d6d3fb9b4788de" || planTag != "91a49269735e274e" {
		t.Fatalf("unexpected A0 identity tags: role=%q session=%q plan=%q", role, sessionTag, planTag)
	}
	if strings.Contains(sessionTag+planTag, token) {
		t.Fatal("A0 identity tags exposed the raw session token")
	}
	for _, malformed := range []string{"ordinary-session", "hh1:x:" + token + ":1", "hh1:i:unsafe/token:1"} {
		if _, _, _, ok := hardHardA0SessionTags(malformed); ok {
			t.Fatalf("malformed Hard-Hard session envelope accepted: %q", malformed)
		}
	}
}
