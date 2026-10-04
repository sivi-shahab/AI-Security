package m365

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"aisec/internal/connector"
	"aisec/internal/connector/connectortest"
	"aisec/internal/connector/m365/m365test"
)

func setup(t *testing.T) (*m365test.Graph, *Graph, *[]time.Duration) {
	t.Helper()
	fake := m365test.New()
	t.Cleanup(fake.Close)
	fake.Drives = []*m365test.Drive{
		{ID: "lib-1", Name: "Dokumen Kredit", Type: "documentLibrary", Items: map[string]*m365test.Item{}},
		{ID: "od-1", Name: "OneDrive Budi", Type: "business", Items: map[string]*m365test.Item{}},
	}
	var waits []time.Duration
	g := &Graph{BaseURL: fake.URL(), HTTP: fake.Client(), Domains: []string{"bankmega.com"}, Backoff: connector.Backoff{Retries: 3,
		Base: time.Second, Max: time.Minute,
		Sleep: func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }}}
	return fake, g, &waits
}

func TestContainersAndDelta(t *testing.T) {
	fake, g, _ := setup(t)
	cs, err := g.Containers(context.Background())
	if err != nil || len(cs) != 2 || cs[0] != (connector.Container{ID: "lib-1", Name: "Dokumen Kredit", Kind: "sharepoint"}) || cs[1].Kind != "onedrive" {
		t.Fatalf("containers %+v %v", cs, err)
	}
	for _, id := range []string{"a", "b", "c"} {
		fake.Put("lib-1", id, m365test.Item{Name: id + ".txt", Path: "/drive/root:", Content: []byte(id)})
	}
	var all []string
	cur := ""
	for {
		p, err := g.Items(context.Background(), cs[0], cur)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range p.Items {
			all = append(all, it.ID)
		}
		cur = p.Next
		if p.Done {
			break
		}
	}
	if !slices.Equal(all, []string{"a", "b", "c"}) {
		t.Fatalf("bootstrap %v", all)
	}
	// Incremental: only what changed, including a sharing change (same cTag) and a deletion.
	fake.Put("lib-1", "b", m365test.Item{Name: "b.txt", Path: "/drive/root:", Content: []byte("b2")})
	fake.Share("lib-1", "c", []map[string]any{m365test.LinkPerm("anonymous")})
	fake.Delete("lib-1", "a")
	p, _ := g.Items(context.Background(), cs[0], cur)
	p2, _ := g.Items(context.Background(), cs[0], p.Next)
	got := append(p.Items, p2.Items...)
	if len(got) != 3 || !got[0].Deleted || got[1].ContentTag != "c:b,2" || got[2].ContentTag != "c:c,1" || !p2.Done {
		t.Errorf("incremental %+v", got)
	}
}

func TestACLMapping(t *testing.T) {
	fake, g, _ := setup(t)
	fake.Put("lib-1", "x", m365test.Item{Name: "x.docx", Content: []byte("x"), Perms: []map[string]any{
		m365test.UserPerm("budi@bankmega.com", "owner"),
		m365test.UserPerm("vendor_mail.com#EXT#@bankmega.onmicrosoft.com", "read"),
		m365test.GroupPerm("Everyone except external users"),
		m365test.LinkPerm("anonymous"),
		m365test.LinkPerm("users", "auditor@kap.co.id"),
		m365test.LinkPerm("organization"),
	}})
	acl, err := g.ACL(context.Background(), connector.Item{ID: "x", ContainerID: "lib-1"})
	want := []connector.Grant{
		{Kind: "user", Ref: "budi@bankmega.com", Role: "owner"},
		{Kind: "user", Ref: "vendor_mail.com#ext#@bankmega.onmicrosoft.com", Role: "read", External: true},
		{Kind: "group", Ref: "Everyone except external users", Role: "read"},
		{Kind: "anyone_link", Role: "read", External: true},
		{Kind: "user", Ref: "auditor@kap.co.id", Role: "read", External: true},
		{Kind: "specific_link", Role: "read", External: true},
		{Kind: "org_link", Role: "read"},
	}
	if err != nil || !slices.Equal(acl, want) {
		t.Errorf("acl:\n got %+v\nwant %+v (%v)", acl, want, err)
	}
}

// AC (ticket 31): Graph rate limits are respected — Retry-After when given, exponential backoff otherwise, and
// a bounded number of retries.
func TestThrottling(t *testing.T) {
	fake, g, waits := setup(t)
	fake.Put("lib-1", "x", m365test.Item{Name: "x.txt", Content: []byte("isi"), Labels: []string{"lbl-conf"}})
	it := connector.Item{ID: "x", ContainerID: "lib-1", Size: 3}

	fake.Throttle["/content"] = &m365test.Throttle{Times: 2, Status: http.StatusTooManyRequests, RetryAfter: "7"}
	if b, err := g.Get(context.Background(), it, 100); err != nil || string(b) != "isi" {
		t.Fatalf("after 429s: %q %v", b, err)
	}
	if !slices.Equal(*waits, []time.Duration{7 * time.Second, 7 * time.Second}) || fake.Count("content:x") != 1 {
		t.Errorf("Retry-After waits %v, fetches %d", *waits, fake.Count("content:x"))
	}

	*waits = nil
	fake.Throttle["/permissions"] = &m365test.Throttle{Times: 3, Status: http.StatusServiceUnavailable}
	if _, err := g.ACL(context.Background(), it); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*waits, []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}) {
		t.Errorf("exponential waits %v", *waits)
	}

	*waits = nil
	fake.Throttle["/extractSensitivityLabels"] = &m365test.Throttle{Times: 10, Status: http.StatusTooManyRequests, RetryAfter: "600"}
	_, err := g.Labels(context.Background(), it)
	var se *connector.StatusError
	if !errors.As(err, &se) || !se.Throttled || len(*waits) != 3 || (*waits)[0] != time.Minute {
		t.Errorf("exhausted: %v, waits %v (capped at MaxBackoff)", err, *waits)
	}
	// Throttling is not "no labels": it surfaces. A file type Graph cannot label is.
	fake.Throttle = map[string]*m365test.Throttle{"/extractSensitivityLabels": {Times: 1, Status: http.StatusBadRequest}}
	if ls, err := g.Labels(context.Background(), it); err != nil || ls != nil {
		t.Errorf("unlabelable: %v %v", ls, err)
	}
	if ls, err := g.Labels(context.Background(), it); err != nil || !slices.Equal(ls, []string{"lbl-conf"}) {
		t.Errorf("labels: %v %v", ls, err)
	}
}

func TestLinksStayOnGraph(t *testing.T) {
	_, g, _ := setup(t)
	if _, err := g.Items(context.Background(), connector.Container{ID: "lib-1"}, "https://evil.example/v1.0/drives/x/root/delta"); err == nil {
		t.Error("followed a delta link off the Graph host")
	}
}

// AC (ticket 32): the M365 connector against the SDK contract.
func TestContract(t *testing.T) {
	fake, g, _ := setup(t)
	connectortest.Run(t, connectortest.Harness{
		Conn: g, Container: "lib-1",
		Put: func(_ *testing.T, name string, b []byte) string {
			fake.Put("lib-1", "id-"+name, m365test.Item{Name: name, Path: "/drive/root:", Content: b})
			return "id-" + name
		},
		Delete: func(_ *testing.T, id string) { fake.Delete("lib-1", id) },
		Share: func(_ *testing.T, id string) {
			fake.Share("lib-1", id, []map[string]any{m365test.LinkPerm("anonymous")})
		},
		SharingInFeed: true,
	})
}
