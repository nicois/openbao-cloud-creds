package credentialakamai

import (
	"strings"
	"testing"

	"github.com/nicois/openbao-cloud-creds/pkg/cloudconfig"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// Grants the incumbent minter reports for itself in these tests. contentAPIID is
// deliberately NOT the Identity-Management api: a successor granted only
// Identity-Management access can rotate again but cannot mint anything a role
// asks for, which is exactly the bug the grant copy fixes.
const (
	selfContentAPIID = 5555
	selfGroupID      = 8888
	accessReadOnly   = "READ-ONLY"
)

// selfGrants builds a self-report with one content api at READ-ONLY, the
// Identity-Management api at READ-ONLY (so the copy has to upgrade it), and one
// group.
func selfGrants(identityAPIID int) (apiAccess, groupAccess interface{}) {
	return map[string]interface{}{
			"allAccessibleApis": false,
			jsonKeyAPIs: []map[string]interface{}{
				{"apiId": selfContentAPIID, "apiName": "CCU APIs", "accessLevel": accessReadOnly},
				{"apiId": identityAPIID, "apiName": identityManagementAPIName, "accessLevel": accessReadOnly},
			},
		},
		map[string]interface{}{jsonKeyGroups: []map[string]interface{}{{"groupId": selfGroupID}}}
}

// grantedLevels flattens a recorded apiAccess body into apiId -> accessLevel.
func grantedLevels(t *testing.T, apiAccess interface{}) map[int]string {
	t.Helper()
	access, ok := apiAccess.(map[string]interface{})
	if !ok {
		t.Fatalf("apiAccess is %T, want an object", apiAccess)
	}
	apis, ok := access[jsonKeyAPIs].([]interface{})
	if !ok {
		t.Fatalf("apiAccess.apis is %T, want an array", access[jsonKeyAPIs])
	}
	out := make(map[int]string, len(apis))
	for _, entry := range apis {
		api, ok := entry.(map[string]interface{})
		if !ok {
			t.Fatalf("apiAccess.apis entry is %T, want an object", entry)
		}
		id, ok := api["apiId"].(float64)
		if !ok {
			t.Fatalf("apiAccess.apis entry has no numeric apiId: %v", api)
		}
		level, _ := api["accessLevel"].(string)
		out[int(id)] = level
	}
	return out
}

// A rotation successor must inherit the incumbent's OWN grants, not a
// construction of what rotation is known to need. Constructing an
// Identity-Management-only grant (as this used to) produced a successor that
// could rotate but could not mint any role's credential — a difference no health
// check can see, because the successor authenticates perfectly.
func TestMinterRotation_SuccessorInheritsIncumbentGrants(t *testing.T) {
	bk, srv, storage := newRotationBackend(t, []interface{}{
		neverExpiresMinter("minter-1", minter1Token),
	})
	srv.SetSelfGrants(selfGrants(srv.IdentityManagementAPIID()))

	resp, err := bk.HandleRequest(t.Context(), &logical.Request{
		Operation: logical.UpdateOperation, Path: rotatePath, Storage: storage,
		Data: map[string]interface{}{fieldMinterID: "minter-1"},
	})
	if err != nil || (resp == nil || resp.IsError()) {
		t.Fatalf("rotate: err=%v resp=%v", err, resp)
	}
	successorID, _ := resp.Data["successor_id"].(string)

	set := loadSetFromStorage(t, storage)
	var successor *cloudconfig.Minter
	for i := range set.Minters {
		if set.Minters[i].ID == successorID {
			successor = &set.Minters[i]
		}
	}
	if successor == nil {
		t.Fatalf("successor %q not in the persisted set", successorID)
	}
	apiAccess, groupAccess := srv.GrantsForClient(successor.RotationParams[clientIDKey])

	levels := grantedLevels(t, apiAccess)
	if got := levels[selfContentAPIID]; got != accessReadOnly {
		t.Fatalf("successor was not granted the incumbent's content api %d at %s, got %q (grant: %v)",
			selfContentAPIID, accessReadOnly, got, levels)
	}
	// The Identity-Management entry is the one exception to a verbatim copy: the
	// successor must be able to create the NEXT successor, so a READ-ONLY grant is
	// upgraded rather than replicated.
	if got := levels[srv.IdentityManagementAPIID()]; got != accessLevelReadWrite {
		t.Fatalf("successor's Identity-Management grant is %q, want %s", got, accessLevelReadWrite)
	}

	groups, ok := groupAccess.(map[string]interface{})
	if !ok {
		t.Fatalf("groupAccess is %T, want the incumbent's object", groupAccess)
	}
	list, ok := groups[jsonKeyGroups].([]interface{})
	if !ok || len(list) != 1 {
		t.Fatalf("successor groupAccess did not replicate the incumbent's groups: %v", groups)
	}
	first, _ := list[0].(map[string]interface{})
	if id, _ := first[jsonKeyGroupID].(float64); int(id) != selfGroupID {
		t.Fatalf("successor groupAccess group is %v, want %d", first, selfGroupID)
	}
}

// Fail closed: without the incumbent's grants there is no safe grant to give the
// successor, so an unreadable self must abort the rotation rather than fall back
// to a narrower one. Called on the client directly so the outcome does not depend
// on which minter the selection logic would pick.
func TestMinterRotation_AbortsWhenIncumbentGrantsUnreadable(t *testing.T) {
	_, srv, _ := newRotationBackend(t, []interface{}{
		neverExpiresMinter("minter-1", minter1Token),
	})
	srv.SetFailHealthForTokenPrefix("ct-1")

	cred, err := parseEdgeGridToken(minter1Token)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	cred.Host = testHost
	client := newAkamaiClient(srv.URL, cred)

	before := srv.ProvisionedCount()
	_, err = client.RotateMinter(t.Context(), cloudconfig.Minter{
		ID: "minter-1", NeverExpires: true,
		RotationParams: map[string]string{usernameKey: testUsername},
	})
	if err == nil {
		t.Fatal("expected rotation to abort when the incumbent's grants cannot be read")
	}
	if !strings.Contains(err.Error(), "own grants") {
		t.Fatalf("error does not explain the failed grant read: %v", err)
	}
	if after := srv.ProvisionedCount(); after != before {
		t.Fatalf("aborted rotation created %d api client(s)", after-before)
	}
}
