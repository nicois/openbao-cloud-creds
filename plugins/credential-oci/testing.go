package credentialoci

// TestSetClient allows tests to inject a fake OCI client into the backend.
// This is exported for use by external test packages (_test).
func TestSetClient(b interface{}, client OCIIAMClient) {
	if bb, ok := b.(*backend); ok {
		bb.SetClient(client)
	}
}

// NewTestFakeClient creates a fake OCI IAM client for testing.
func NewTestFakeClient() OCIIAMClient {
	return newFakeOCIClient()
}
