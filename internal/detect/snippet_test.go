package detect

import (
	"regexp"
	"strings"
	"testing"
)

func TestSnippetAndWithout(t *testing.T) {
	text := strings.Repeat("kata pengantar ", 20) + "NIK nasabah 3171012309850001 dan kartu 4111 1111 1111 1111, ref 998877665544332211. " +
		strings.Repeat("penutup surat ", 20)
	r := Scan(text)
	sn := Snippet(text, r.Matches)
	if len(sn) > SnippetMax || !strings.Contains(sn, "[REDACTED:") || regexp.MustCompile(`\d(?:[ -]?\d){11,}`).MatchString(sn) {
		t.Fatalf("snippet %d bytes: %q", len(sn), sn)
	}
	if Snippet(text, nil) == "" || len(Snippet("pendek", nil)) != len("pendek") {
		t.Fatal("snippet without matches")
	}
	// Dropping the card class leaves the NIK class; dropping both leaves internal.
	var types []string
	for _, c := range r.Classes {
		types = append(types, c.Type)
	}
	if len(types) < 2 || r.Sensitivity != "confidential" {
		t.Fatalf("scan: %+v", r.Classes)
	}
	w := Without(r, "PCI.PAN")
	for _, c := range w.Classes {
		if c.Type == "PCI.PAN" {
			t.Fatal("PAN not dropped")
		}
	}
	if len(w.Classes) != len(r.Classes)-1 || w.Sensitivity != "confidential" {
		t.Fatalf("without PAN: %+v", w)
	}
	if all := Without(r, types...); len(all.Classes) != 0 || all.Sensitivity != "internal" || len(all.Matches) != 0 {
		t.Fatalf("without all: %+v", all)
	}
}
