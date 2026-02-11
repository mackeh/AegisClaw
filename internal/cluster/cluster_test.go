package cluster

import (
	"testing"
)

func TestNewNode(t *testing.T) {
	n := NewNode("node-1", "localhost:9090", RoleLeader, "0.5.0")
	if n == nil {
		t.Fatal("expected non-nil node")
	}

	info := n.Info()
	if info.ID != "node-1" {
		t.Errorf("expected id 'node-1', got '%s'", info.ID)
	}
	if info.Role != RoleLeader {
		t.Errorf("expected role 'leader', got '%s'", info.Role)
	}
	if info.Status != "online" {
		t.Errorf("expected status 'online', got '%s'", info.Status)
	}
}

func TestNode_RegisterPeer(t *testing.T) {
	n := NewNode("node-1", ":9090", RoleLeader, "0.5.0")

	n.RegisterPeer(NodeInfo{ID: "node-2", Address: ":9091", Role: RoleFollower, Status: "online"})
	n.RegisterPeer(NodeInfo{ID: "node-3", Address: ":9092", Role: RoleFollower, Status: "online"})

	peers := n.Peers()
	if len(peers) != 2 {
		t.Errorf("expected 2 peers, got %d", len(peers))
	}
}

func TestNode_RemovePeer(t *testing.T) {
	n := NewNode("node-1", ":9090", RoleLeader, "0.5.0")
	n.RegisterPeer(NodeInfo{ID: "node-2", Address: ":9091", Role: RoleFollower, Status: "online"})

	n.RemovePeer("node-2")

	peers := n.Peers()
	if len(peers) != 0 {
		t.Errorf("expected 0 peers after removal, got %d", len(peers))
	}
}

func TestNode_IsLeader(t *testing.T) {
	leader := NewNode("node-1", ":9090", RoleLeader, "0.5.0")
	follower := NewNode("node-2", ":9091", RoleFollower, "0.5.0")

	if !leader.IsLeader() {
		t.Error("expected node to be leader")
	}
	if follower.IsLeader() {
		t.Error("expected node to not be leader")
	}
}

func TestNode_Status(t *testing.T) {
	n := NewNode("node-1", ":9090", RoleLeader, "0.5.0")
	n.RegisterPeer(NodeInfo{ID: "node-2", Address: ":9091", Role: RoleFollower, Status: "online"})
	n.RegisterPeer(NodeInfo{ID: "node-3", Address: ":9092", Role: RoleFollower, Status: "offline"})

	status := n.Status()
	if status.NodeCount != 3 {
		t.Errorf("expected 3 nodes, got %d", status.NodeCount)
	}
	if status.OnlineNodes != 2 {
		t.Errorf("expected 2 online nodes, got %d", status.OnlineNodes)
	}
}

func TestNode_ForwardAudit(t *testing.T) {
	n := NewNode("node-1", ":9090", RoleFollower, "0.5.0")

	// Should not block
	n.ForwardAudit(AuditEvent{NodeID: "node-1", Action: "test"})
	n.ForwardAudit(AuditEvent{NodeID: "node-1", Action: "test2"})

	// Drain events
	evt := <-n.events
	if evt.Action != "test" {
		t.Errorf("expected action 'test', got '%s'", evt.Action)
	}
}

func TestNode_Stop(t *testing.T) {
	n := NewNode("node-1", ":9090", RoleLeader, "0.5.0")
	n.Stop()

	info := n.Info()
	if info.Status != "offline" {
		t.Errorf("expected status 'offline' after stop, got '%s'", info.Status)
	}
}
