package credentialoci

import "time"

// cloudName is the cloud identifier used in stored config, response envelopes,
// and the "cloud" metric label.
const cloudName = "oci"

// Field and metric-label names that recur across schemas, responses, and
// telemetry. Constified so the linter (goconst) has a single source of truth.
const (
	fieldName      = "name"
	fieldRole      = "role"
	fieldCloud     = "cloud"
	fieldMinterSet = "minter_set"
	fieldSlotIndex = "slot_index"
	fieldSlotCount = "slot_count"
	fieldUserOCID  = "user_ocid"
	fieldRotation  = "rotation_period"
)

// descRoleName is the shared field description for the role-name parameter.
const descRoleName = "Name of the role"

// metricNamespace is the leading segment of every metric key this plugin emits.
const metricNamespace = "cloud_creds"

const (
	// healthCheckInterval is how often the health-check worker probes minters,
	// and the recovery state machine's re-probe cadence.
	healthCheckInterval = 5 * time.Minute

	// authFailThreshold is how long upstream auth must keep failing before the
	// recovery state machine declares a minter hard-failed.
	authFailThreshold = 30 * time.Second
)
