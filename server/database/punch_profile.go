package database

import (
	"encoding/json"
	"errors"
	"net/netip"
)

// PunchProfile is an optional capability in a generation-bound peer offer or
// answer. Old devices omit the whole object and continue using candidate_sources.
type PunchProfile struct {
	NATType          string           `json:"nat_type"`
	PortStep         int32            `json:"port_step"`
	PortHint         uint16           `json:"port_hint"`
	UPnPMappedAddr   *netip.AddrPort  `json:"upnp_mapped_addr"`
	TCPCandidates    []netip.AddrPort `json:"tcp_candidates,omitempty"`
	SupportsSymPunch bool             `json:"supports_sym_punch"`
}

// UnmarshalJSON supplies the same old-client defaults as the Rust receiver.
func (p *PunchProfile) UnmarshalJSON(data []byte) error {
	type fields PunchProfile
	profile := fields{NATType: "None"}
	if err := json.Unmarshal(data, &profile); err != nil {
		return err
	}
	*p = PunchProfile(profile)
	return nil
}

func (p *PunchProfile) Validate() error {
	if p == nil {
		return nil
	}
	switch p.NATType {
	case "None", "Cone", "RandomSymmetric":
		if p.PortStep != 0 {
			return errors.New("unexpected port step")
		}
	case "LinearSymmetric":
		if p.PortStep == 0 || p.PortStep < -32768 || p.PortStep > 32767 || p.PortHint == 0 {
			return errors.New("invalid linear profile")
		}
	default:
		return errors.New("unknown NAT kind")
	}
	if len(p.TCPCandidates) > 16 {
		return errors.New("too many TCP candidates")
	}
	valid := func(a netip.AddrPort) bool {
		return a.IsValid() && a.Port() != 0 && !a.Addr().IsUnspecified() && !a.Addr().IsMulticast() && a.Addr().Zone() == ""
	}
	if p.UPnPMappedAddr != nil && !valid(*p.UPnPMappedAddr) {
		return errors.New("invalid mapped address")
	}
	seen := make(map[netip.AddrPort]bool, len(p.TCPCandidates))
	for _, a := range p.TCPCandidates {
		if !valid(a) || seen[a] {
			return errors.New("invalid TCP candidate")
		}
		seen[a] = true
	}
	return nil
}
