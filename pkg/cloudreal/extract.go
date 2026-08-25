package cloudreal

import (
	"encoding/json"
	"fmt"
)

// FirstStringField pulls a value out of a JSON response without modelling the whole schema —
// which is the point, since the schema is what is being discovered. Numbers are returned as
// strings, because a probe cares whether a field was present far more than what type it had.
func FirstStringField(body, field string) string {
	var parsed interface{}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return ""
	}
	return findField(parsed, field)
}

// findField walks the decoded document depth-first and returns the first match.
func findField(value interface{}, field string) string {
	switch typed := value.(type) {
	case map[string]interface{}:
		if found, ok := typed[field]; ok {
			if got := scalarString(found); got != "" {
				return got
			}
		}
		for _, nested := range typed {
			if got := findField(nested, field); got != "" {
				return got
			}
		}
	case []interface{}:
		for _, nested := range typed {
			if got := findField(nested, field); got != "" {
				return got
			}
		}
	}
	return ""
}

// scalarString renders the leaf types a probe cares about, and nothing else: an object or an
// array under the requested name means the value is nested deeper, so the walk continues.
func scalarString(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		return fmt.Sprintf("%.0f", typed)
	default:
		return ""
	}
}
