package metrics

import "os"

// nodeIDEnvVar is the node-local override for this node's metrics ID. It must
// be node-local (per-process), NOT a persisted config field: PluginConfig is
// stored in logical.Storage, which raft replicates across nodes — a persisted
// override would make every node share one ID and collapse the per-node
// keyspace the cross-node merge depends on.
const nodeIDEnvVar = "OPENBAO_CLOUD_CREDS_NODE_ID"

// unknownNodeID is the last-resort fallback when neither the env override nor
// the OS hostname is available.
const unknownNodeID = "unknown-node"

// ResolveNodeID returns this node's stable, node-local metrics ID:
// $OPENBAO_CLOUD_CREDS_NODE_ID, else os.Hostname(), else "unknown-node".
func ResolveNodeID() string {
	if id := os.Getenv(nodeIDEnvVar); id != "" {
		return id
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		return host
	}
	return unknownNodeID
}
