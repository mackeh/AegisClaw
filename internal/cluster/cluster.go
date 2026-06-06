// Package cluster provides multi-node orchestration for AegisClaw instances.
// It enables centralized policy management, audit log aggregation, and
// coordinated skill execution across a cluster of AegisClaw nodes.
package cluster

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// NodeRole defines the role of a node in the cluster.
type NodeRole string

const (
	RoleLeader   NodeRole = "leader"   // Manages policy, aggregates audit logs
	RoleFollower NodeRole = "follower" // Executes skills, reports to leader
)

// NodeInfo describes a single AegisClaw node in the cluster.
type NodeInfo struct {
	ID        string    `json:"id"`
	Address   string    `json:"address"`
	Role      NodeRole  `json:"role"`
	Version   string    `json:"version"`
	Status    string    `json:"status"` // online, offline, degraded
	LastSeen  time.Time `json:"last_seen"`
	Skills    int       `json:"skills"`    // number of installed skills
	Uptime    string    `json:"uptime"`
}

// AuditEvent is an audit entry forwarded from a follower to the leader.
type AuditEvent struct {
	NodeID    string         `json:"node_id"`
	Timestamp time.Time      `json:"timestamp"`
	Action    string         `json:"action"`
	Decision  string         `json:"decision"`
	Details   map[string]any `json:"details,omitempty"`
}

// PolicyUpdate is a policy change pushed from leader to followers.
type PolicyUpdate struct {
	PolicyID  string `json:"policy_id"`
	Content   []byte `json:"content"`
	Hash      string `json:"hash"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Node represents this AegisClaw instance in the cluster.
type Node struct {
	mu       sync.RWMutex
	info     NodeInfo
	peers    map[string]*NodeInfo
	server   *grpc.Server
	leader   string // address of the leader node
	events   chan AuditEvent
	policies chan PolicyUpdate
}

// NewNode creates a new cluster node.
func NewNode(id, address string, role NodeRole, version string) *Node {
	return &Node{
		info: NodeInfo{
			ID:       id,
			Address:  address,
			Role:     role,
			Version:  version,
			Status:   "online",
			LastSeen: time.Now(),
		},
		peers:    make(map[string]*NodeInfo),
		events:   make(chan AuditEvent, 1024),
		policies: make(chan PolicyUpdate, 16),
	}
}

// Info returns the current node info.
func (n *Node) Info() NodeInfo {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.info
}

// Peers returns all known peer nodes.
func (n *Node) Peers() []NodeInfo {
	n.mu.RLock()
	defer n.mu.RUnlock()
	var peers []NodeInfo
	for _, p := range n.peers {
		peers = append(peers, *p)
	}
	return peers
}

// RegisterPeer adds a peer node to the cluster.
func (n *Node) RegisterPeer(peer NodeInfo) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.peers[peer.ID] = &peer
}

// RemovePeer removes a peer from the cluster.
func (n *Node) RemovePeer(id string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.peers, id)
}

// ForwardAudit sends an audit event to the leader for aggregation.
func (n *Node) ForwardAudit(evt AuditEvent) {
	select {
	case n.events <- evt:
	default:
		// Drop if buffer full
	}
}

// StartServer starts the gRPC server for inter-node communication.
func (n *Node) StartServer(ctx context.Context) error {
	lis, err := net.Listen("tcp", n.info.Address)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	n.server = grpc.NewServer()
	// TODO: Register gRPC service implementations
	// pb.RegisterClusterServiceServer(n.server, &clusterServiceImpl{node: n})

	go func() {
		<-ctx.Done()
		n.server.GracefulStop()
	}()

	return n.server.Serve(lis)
}

// Stop gracefully shuts down the node.
func (n *Node) Stop() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.info.Status = "offline"
	if n.server != nil {
		n.server.GracefulStop()
	}
	close(n.events)
	close(n.policies)
}

// ConnectToLeader establishes a gRPC connection to the leader node.
func (n *Node) ConnectToLeader(leaderAddr string) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(leaderAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("connect to leader: %w", err)
	}
	n.leader = leaderAddr
	return conn, nil
}

// IsLeader returns true if this node is the cluster leader.
func (n *Node) IsLeader() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.info.Role == RoleLeader
}

// ClusterStatus returns a summary of the cluster state.
type ClusterStatus struct {
	NodeCount   int        `json:"node_count"`
	Leader      string     `json:"leader"`
	OnlineNodes int        `json:"online_nodes"`
	Nodes       []NodeInfo `json:"nodes"`
}

// Status returns the current cluster status from this node's perspective.
func (n *Node) Status() ClusterStatus {
	n.mu.RLock()
	defer n.mu.RUnlock()

	status := ClusterStatus{
		NodeCount: len(n.peers) + 1,
		Leader:    n.leader,
		Nodes:     []NodeInfo{n.info},
	}

	online := 1 // this node
	for _, p := range n.peers {
		status.Nodes = append(status.Nodes, *p)
		if p.Status == "online" {
			online++
		}
	}
	status.OnlineNodes = online
	return status
}

// SyncPolicies returns a channel for receiving policy updates.
func (n *Node) SyncPolicies() <-chan PolicyUpdate {
	return n.policies
}

// PushPolicy broadcasts a policy update to all followers (Leader only).
func (n *Node) PushPolicy(update PolicyUpdate) {
	if !n.IsLeader() {
		return
	}
	n.mu.RLock()
	defer n.mu.RUnlock()

	fmt.Printf("📢 Broadcasting policy update: %s (hash: %s)\n", update.PolicyID, update.Hash)
	// In a real gRPC implementation, we would call the SyncPolicy RPC on all peers.
	// For the simulation, we'll just log it.
}

// GetAuditStream returns the stream of incoming audit events (Leader only).
func (n *Node) GetAuditStream() <-chan AuditEvent {
	return n.events
}
