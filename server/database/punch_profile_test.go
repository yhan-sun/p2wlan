package database

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestNegotiatedSignalContractAndDelivery(t *testing.T) {
	data, err := os.ReadFile("../../contracts/fixtures/negotiated_signal.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract Signal
	if err := json.Unmarshal(data, &contract); err != nil {
		t.Fatal(err)
	}
	if contract.NATProfile == nil || contract.NATProfile.Validate() != nil || contract.NATProfile.PortStep != -4 || !contract.NATProfile.UDPEndpointReceipts {
		t.Fatalf("profile: %#v", contract.NATProfile)
	}
	var raw struct {
		Profile json.RawMessage `json:"nat_profile"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(contract.NATProfile)
	if err != nil {
		t.Fatal(err)
	}
	var expected, actual map[string]any
	if err := json.Unmarshal(raw.Profile, &expected); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &actual); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("different wire values %v %v", actual, expected)
	}
	db := openSignalLeaseDB(t)
	sender, target := createLeasePair(t, db)
	send := func(p *PunchProfile) {
		t.Helper()
		_, err := db.CreateAuthorizedSignalWithProfile(p, sender, target, contract.Type, 0, contract.Candidates, nil, "", 0, contract.CandidateGeneration, time.Now().Add(30*time.Second).UnixMilli(), "paired", "", "sender-key")
		if err != nil {
			t.Fatal(err)
		}
	}
	send(contract.NATProfile)
	leased, _, err := db.ListSignalsWithLease(target)
	if err != nil || len(leased) != 1 || !reflect.DeepEqual(leased[0].NATProfile, contract.NATProfile) {
		t.Fatalf("lease %v %v", leased, err)
	}
	if count, err := db.AckSignals(target, []SignalAck{{ID: leased[0].ID, DeliveryToken: leased[0].DeliveryToken}}); err != nil || count != 1 {
		t.Fatalf("ack %d %v", count, err)
	}
	send(contract.NATProfile)
	send(nil)
	legacy, err := db.ListAndDeleteSignals(target)
	if err != nil || len(legacy) != 2 || !reflect.DeepEqual(legacy[0].NATProfile, contract.NATProfile) || legacy[1].NATProfile != nil {
		t.Fatalf("legacy delivery %v %v", legacy, err)
	}
	var old Signal
	if err := json.Unmarshal([]byte(`{"type":"peer_offer","from_node_id":"a"}`), &old); err != nil || old.NATProfile != nil {
		t.Fatalf("legacy receiver %v %v", old, err)
	}
	var partial PunchProfile
	if err := json.Unmarshal([]byte("{}"), &partial); err != nil || partial.NATType != "None" || partial.UDPEndpointReceipts || partial.Validate() != nil {
		t.Fatalf("partial %v %v", partial, err)
	}
}

func TestNegotiatedProfileRejectsInvalidCandidates(t *testing.T) {
	for _, value := range []string{
		`{"nat_type":"unknown"}`, `{"nat_type":"LinearSymmetric","port_step":0,"port_hint":42}`,
		`{"nat_type":"LinearSymmetric","port_step":32768,"port_hint":12}`,
		`{"nat_type":"Cone","port_step":1}`, `{"nat_type":"Cone","upnp_mapped_addr":"0.0.0.0:100"}`,
		`{"tcp_candidates":["[ff02::1]:443"]}`, `{"tcp_candidates":["127.0.0.1:1","127.0.0.1:1"]}`,
		`{"tcp_simultaneous_open":true}`,
	} {
		var profile PunchProfile
		if err := json.Unmarshal([]byte(value), &profile); err == nil && profile.Validate() == nil {
			t.Errorf("invalid profile accepted: %s", value)
		}
	}
}

func TestNegotiatedTCPOnlyOfferWithEmptyUDPList(t *testing.T) {
	data, err := os.ReadFile("../../contracts/fixtures/negotiated_tcp_only_signal.json")
	if err != nil {
		t.Fatal(err)
	}
	var signal Signal
	if err := json.Unmarshal(data, &signal); err != nil {
		t.Fatal(err)
	}
	profile := signal.NATProfile
	if profile == nil || profile.Validate() != nil || profile.PortHint != 0 || profile.SupportsSymPunch || !profile.TCPSimultaneousOpen || len(profile.TCPCandidates) != 1 || len(signal.Candidates) != 0 {
		t.Fatal("invalid TCP-only offer")
	}
	db := openSignalLeaseDB(t)
	a, b := createLeasePair(t, db)
	_, err = db.CreateAuthorizedSignalWithProfile(profile, a, b, signal.Type, 0, signal.Candidates, nil, "", 0, signal.CandidateGeneration, time.Now().Add(30*time.Second).UnixMilli(), "paired", "", "sender-key")
	if err != nil {
		t.Fatal(err)
	}
	rows, _, err := db.ListSignalsWithLease(b)
	if err != nil || len(rows) != 1 || len(rows[0].Candidates) != 0 || !reflect.DeepEqual(rows[0].NATProfile, profile) {
		t.Fatalf("TCP-only signal delivery: %#v, %v", rows, err)
	}
}
