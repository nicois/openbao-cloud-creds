package cloudconfig

import "testing"

// TestCloudKeyIDIsWhatAnEscalationQuotes is the A23 guard. Minter.ID is a label the
// operator invented and no cloud audit log contains it, so when a provider escalates
// about a key nothing mapped it back to a mount, set or role.
func TestCloudKeyIDIsWhatAnEscalationQuotes(t *testing.T) {
	t.Run("from a rotation record", func(t *testing.T) {
		m := Minter{ID: "primary", RotationParams: map[string]string{"access_key_id": "AKIAEXAMPLE"}}
		if got := CloudKeyID(m, "access_key_id"); got != "AKIAEXAMPLE" {
			t.Errorf("CloudKeyID = %q, want the recorded upstream id", got)
		}
	})

	t.Run("from the public half of a composite token", func(t *testing.T) {
		m := Minter{ID: "primary", Token: "AKIAPUBLICPART:thisIsTheSecret"}
		got := CloudKeyID(m)
		if got != "AKIAPUBLICPART" {
			t.Errorf("CloudKeyID = %q, want the public half", got)
		}
		if got == m.Token || len(got) >= len(m.Token) {
			t.Error("CloudKeyID returned the whole token; only the part before the colon is " +
				"publishable, and this value goes into metric labels and log lines")
		}
	})

	t.Run("never leaks the secret half", func(t *testing.T) {
		const secret = "superSecretValue"
		m := Minter{ID: "primary", Token: "public-id:" + secret}
		if got := CloudKeyID(m); got == secret || len(got) > len("public-id") {
			t.Errorf("CloudKeyID = %q, which contains or exceeds the public half — a metric label "+
				"carrying secret material would be published to every scrape", got)
		}
	})

	t.Run("empty when the cloud gives us nothing", func(t *testing.T) {
		// DO and UpCloud store a single opaque secret: there is no public id to publish,
		// and an empty label is better than a fabricated one.
		if got := CloudKeyID(Minter{ID: "primary", Token: "dop_v1_opaquesecret"}); got != "" {
			t.Errorf("CloudKeyID = %q for a single-secret token, want empty", got)
		}
	})

	t.Run("a rotation record wins over the token", func(t *testing.T) {
		m := Minter{ID: "primary", Token: "stale-public:secret",
			RotationParams: map[string]string{"key_id": "current-upstream-id"}}
		if got := CloudKeyID(m, "key_id"); got != "current-upstream-id" {
			t.Errorf("CloudKeyID = %q, want the rotation-recorded id, which is authoritative", got)
		}
	})
}
