package totp

import (
	"fmt"
	"net/url"
)

// ParseSeed accepts a second-factor seed in either form real credentials are stored in: a
// bare base32 secret, or an `otpauth://totp/...` enrolment URL.
//
// The URL form is validated rather than trusted, because the parameters it carries are the
// ones this code assumes: SHA1, six digits, a thirty-second period. A seed enrolled with
// different parameters would produce codes that are wrong in a way that looks exactly like a
// wrong password, and a rejected second factor may cost the session.
func ParseSeed(seed string) (string, error) {
	if seed == "" {
		return "", fmt.Errorf("the second-factor seed is empty")
	}
	parsed, err := url.Parse(seed)
	if err != nil || parsed.Scheme == "" {
		// Not a URL: treat it as a bare secret and let the base32 decode validate it.
		return seed, nil
	}
	if parsed.Scheme != "otpauth" {
		return "", fmt.Errorf("seed URL scheme is %q, want otpauth", parsed.Scheme)
	}
	if parsed.Host != "totp" {
		return "", fmt.Errorf("seed URL type is %q, want totp", parsed.Host)
	}

	query := parsed.Query()
	for field, want := range map[string]string{"algorithm": "SHA1", "digits": "6", "period": "30"} {
		// An absent parameter means the enrolment default, which matches what we assume;
		// a PRESENT parameter that disagrees does not, and must not be ignored.
		if got := query.Get(field); got != "" && got != want {
			return "", fmt.Errorf("seed URL says %s=%s, but this implementation assumes %s", field, got, want)
		}
	}
	secret := query.Get("secret")
	if secret == "" {
		return "", fmt.Errorf("seed URL carries no secret parameter")
	}
	return secret, nil
}
