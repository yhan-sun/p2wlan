package database

import "testing"

func TestAdminTopologyRendersPrivateDefaultDevicesWithoutCrossAccountNetwork(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedAdminTestData(t, db)

	statements := []string{
		`INSERT INTO devices (id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, last_seen, app_version, online, created_at) VALUES ('default-u1', 'u1', 'default', 'pk-default-u1', 'Alice Personal', 'macos', '10.20.0.10', 'unknown', 120, '0.1.163', 1, 120)`,
		`INSERT INTO devices (id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, last_seen, app_version, online, created_at) VALUES ('default-u2', 'u2', 'default', 'pk-default-u2', 'Bob Personal', 'windows', '10.20.0.11', 'unknown', 121, '0.1.163', 1, 121)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("seed default device: %v", err)
		}
	}

	global, err := db.AdminTopology("")
	if err != nil {
		t.Fatal(err)
	}
	nodes := map[string]AdminTopologyNode{}
	for _, node := range global.Nodes {
		nodes[node.ID] = node
	}
	if _, ok := nodes["network:default"]; ok {
		t.Fatal("legacy shared default network must never be rendered as a shared topology node")
	}
	for _, id := range []string{"device:default-u1", "device:default-u2"} {
		if _, ok := nodes[id]; !ok {
			t.Fatalf("expected private default device %s in global topology", id)
		}
	}

	attachments := map[string]string{}
	for _, edge := range global.Edges {
		if edge.ID == "personal-attachment:default-u1" || edge.ID == "personal-attachment:default-u2" {
			attachments[edge.Target] = edge.Source
		}
	}
	if attachments["device:default-u1"] != "account:u1" || attachments["device:default-u2"] != "account:u2" {
		t.Fatalf("default devices must attach directly to their owners: %+v", attachments)
	}

	focused, err := db.AdminTopology("u1")
	if err != nil {
		t.Fatal(err)
	}
	focusedNodes := map[string]AdminTopologyNode{}
	for _, node := range focused.Nodes {
		focusedNodes[node.ID] = node
	}
	if _, ok := focusedNodes["device:default-u1"]; !ok {
		t.Fatal("focused account topology must include its private default device")
	}
	if _, ok := focusedNodes["device:default-u2"]; ok {
		t.Fatal("legacy default membership must not expose another account's private device")
	}
}
