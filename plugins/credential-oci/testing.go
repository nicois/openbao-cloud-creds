package credentialoci

// TestSetClient routes every per-set minter through the given fake OCI client.
// It registers a client factory that ignores the minter token and returns the
// fake, so slot provisioning/rotation exercises the set-aware selector against
// an in-memory backend. Exported for use by external test packages (_test).
func TestSetClient(b interface{}, client OCIIAMClient) {
	if bb, ok := b.(*backend); ok {
		bb.SetClientFactory(func(string) OCIIAMClient { return client })
	}
}

// NewTestFakeClient creates a fake OCI IAM client for testing.
func NewTestFakeClient() OCIIAMClient {
	return newFakeOCIClient()
}
