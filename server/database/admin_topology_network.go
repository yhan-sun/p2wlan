package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrAdminNetworkNotFound = errors.New("admin network not found")

// A network lookup is independent of the global account cursor. Its graph is
// a bounded, transaction-consistent relationship snapshot, never a path proof.
func (db *DB) AdminTopologyNetwork(ctx context.Context, networkID string, nodeBudget int) (*AdminTopologyPage, error) {
	_, nodeBudget = normalizeAdminTopologyPage(1, nodeBudget)
	networkID = strings.TrimSpace(networkID)
	personal := strings.HasPrefix(networkID, "personal:")
	owner := strings.TrimPrefix(networkID, "personal:")
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	page := &AdminTopologyPage{AdminTopology: AdminTopology{
		GeneratedAt: time.Now().Unix(), GraphKind: "control_relationships", Scope: "network", FocusNetworkID: networkID,
		PathObservationNote: "Bounded network membership, device attachment and pending signaling; daemon path observations remain separate in Connections.",
		Nodes:               []AdminTopologyNode{}, Edges: []AdminTopologyEdge{},
	}, NodeBudget: nodeBudget, EdgeBudget: adminTopologyGlobalEdgeBudget}
	root := AdminTopologyNode{ID: "network:" + networkID, NetworkID: networkID, Kind: "network", Focus: true}
	if personal {
		root.ID, root.Kind, root.AccountID, root.NetworkID = "account:"+owner, "account", owner, ""
		err = tx.QueryRowContext(ctx, `SELECT COALESCE(NULLIF(username,''),email) FROM users WHERE id=? AND id<>'system'`, owner).Scan(&root.Label)
		root.Username = root.Label
		page.FocusAccountID = owner
	} else {
		var isRoom bool
		err = tx.QueryRowContext(ctx, `SELECT n.name,n.cidr,n.owner_id,EXISTS(SELECT 1 FROM rooms r WHERE r.network_id=n.id),
   COALESCE((SELECT room_code FROM rooms r WHERE r.network_id=n.id),'') FROM networks n WHERE n.id=? AND n.id<>'default'`, networkID).
			Scan(&root.Label, &root.CIDR, &root.OwnerID, &isRoom, &root.RoomCode)
		if isRoom {
			root.Kind = "room"
		}
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAdminNetworkNotFound
	}
	if err != nil {
		return nil, err
	}
	page.Nodes = append(page.Nodes, root)
	if personal {
		page.LoadedAccounts, page.TotalAccounts = 1, 1
	} else if err := adminNetworkMembers(ctx, tx, networkID, page); err != nil {
		return nil, err
	}
	if err := adminNetworkDevices(ctx, tx, networkID, owner, personal, page); err != nil {
		return nil, err
	}
	if err := adminNetworkSignals(ctx, tx, networkID, owner, personal, page); err != nil {
		return nil, err
	}
	page.Complete = !page.Partial
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return page, nil
}

func adminNetworkMembers(ctx context.Context, tx *sql.Tx, network string, page *AdminTopologyPage) error {
	const from = ` FROM network_memberships m JOIN users u ON u.id=m.user_id WHERE m.network_id=? AND u.id<>'system'`
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*)`+from, network).Scan(&page.TotalAccounts); err != nil {
		return err
	}
	remaining := page.NodeBudget - len(page.Nodes)
	rows, err := tx.QueryContext(ctx, `SELECT u.id,COALESCE(NULLIF(u.username,''),u.email),m.role`+from+` ORDER BY u.id ASC LIMIT ?`, network, remaining+1)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, name, role string
		if err := rows.Scan(&id, &name, &role); err != nil {
			return err
		}
		if len(page.Nodes) >= page.NodeBudget {
			page.Partial, page.PartialReason = true, "node_budget"
			break
		}
		page.Nodes = append(page.Nodes, AdminTopologyNode{ID: "account:" + id, Kind: "account", AccountID: id, Username: name, Label: name})
		page.Edges = append(page.Edges, AdminTopologyEdge{ID: "membership:" + id + ":" + network, Source: "account:" + id, Target: "network:" + network, Kind: "membership", Role: role})
		page.LoadedAccounts++
	}
	return rows.Err()
}

func adminNetworkDevices(ctx context.Context, tx *sql.Tx, network, owner string, personal bool, page *AdminTopologyPage) error {
	where, args := `d.network_id=?`, []any{network}
	target, role := "network:"+network, ""
	if personal {
		where, args = `d.network_id='default' AND d.user_id=?`, []any{owner}
		target, role = "account:"+owner, "private-default"
	}
	args = append(args, page.NodeBudget-len(page.Nodes)+1)
	rows, err := tx.QueryContext(ctx, `SELECT `+adminDeviceColumns()+`
  FROM devices d JOIN users u ON u.id=d.user_id LEFT JOIN networks n ON n.id=d.network_id
  WHERE `+where+` ORDER BY d.id ASC LIMIT ?`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	cutoff := page.GeneratedAt - DeviceOnlineTTL
	for rows.Next() {
		item, err := scanAdminDevice(rows, cutoff)
		if err != nil {
			return err
		}
		if len(page.Nodes) >= page.NodeBudget {
			page.Partial, page.PartialReason = true, "node_budget"
			break
		}
		online := item.Online
		page.Nodes = append(page.Nodes, AdminTopologyNode{ID: "device:" + item.ID, Kind: "device", Label: item.DeviceName,
			AccountID: item.OwnerID, Username: item.Username, NetworkID: item.NetworkID, VirtualIP: item.VirtualIP, Platform: item.Platform,
			NATType: item.NATType, AppVersion: item.AppVersion, RelayRTTMS: item.RelayRTTMS, LastSeen: item.LastSeen, Online: &online})
		page.Edges = append(page.Edges, AdminTopologyEdge{ID: "attachment:" + item.ID, Source: target, Target: "device:" + item.ID, Kind: "attachment", Role: role})
	}
	return rows.Err()
}

func adminNetworkSignals(ctx context.Context, tx *sql.Tx, network, owner string, personal bool, page *AdminTopologyPage) error {
	where, args := `f.network_id=? AND t.network_id=?`, []any{network, network}
	if personal {
		where, args = `f.network_id='default' AND t.network_id='default' AND f.user_id=? AND t.user_id=?`, []any{owner, owner}
	}
	where += ` AND s.created_at >= ?`
	args = append(args, page.GeneratedAt-signalTTLSeconds)
	args = append(args, page.EdgeBudget-len(page.Edges)+1)
	rows, err := tx.QueryContext(ctx, `SELECT s.from_node_id,s.to_node_id,s.type,COUNT(*),MAX(s.created_at)
  FROM signals s JOIN devices f ON f.id=s.from_node_id JOIN devices t ON t.id=s.to_node_id
  WHERE `+where+` GROUP BY s.from_node_id,s.to_node_id,s.type ORDER BY MAX(s.created_at) DESC,s.from_node_id,s.to_node_id,s.type LIMIT ?`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	nodes := make(map[string]bool, len(page.Nodes))
	for _, node := range page.Nodes {
		nodes[node.ID] = true
	}
	for rows.Next() {
		var from, to, kind string
		var count int
		var created int64
		if err := rows.Scan(&from, &to, &kind, &count, &created); err != nil {
			return err
		}
		if len(page.Edges) >= page.EdgeBudget {
			page.Partial = true
			if page.PartialReason == "" {
				page.PartialReason = "edge_budget"
			}
			break
		}
		if !nodes["device:"+from] || !nodes["device:"+to] {
			continue
		}
		page.Edges = append(page.Edges, AdminTopologyEdge{ID: fmt.Sprintf("signal:%s:%s:%s", from, to, kind), Source: "device:" + from, Target: "device:" + to, Kind: "pending_signal", SignalType: kind, Count: count, CreatedAt: created})
	}
	return rows.Err()
}
