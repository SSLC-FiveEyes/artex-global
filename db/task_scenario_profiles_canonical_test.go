package db

import "testing"

func TestCanonicalProfileJSONSortsNestedKeysAndKeepsNumbers(t *testing.T) {
	a, err := canonicalProfileJSON([]byte(`{"scope": {"max_requests": 9007199254740993, "approved_ports": [80, 443]}, "allowed_tools": ["record_fact"]}`))
	if err != nil {
		t.Fatal(err)
	}
	// Same document as PostgreSQL JSONB would return it: re-ordered keys, spaces.
	b, err := canonicalProfileJSON([]byte(`{"scope": {"approved_ports": [80, 443], "max_requests": 9007199254740993}, "allowed_tools": ["record_fact"]}`))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"allowed_tools":["record_fact"],"scope":{"approved_ports":[80,443],"max_requests":9007199254740993}}`
	if string(a) != want || string(b) != want {
		t.Fatalf("canonical mismatch:\n a=%s\n b=%s", a, b)
	}
}

func TestCanonicalProfileJSONRejectsNonObjects(t *testing.T) {
	for _, in := range []string{`[]`, `"x"`, `null`, `{"a":1} {"b":2}`, `{`} {
		if _, err := canonicalProfileJSON([]byte(in)); err == nil {
			t.Fatalf("accepted %q", in)
		}
	}
}
