package gdrive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"aisec/internal/connector"
	"aisec/internal/connector/connectortest"
)

// fakeDrive is the Drive v3, Directory and Reports APIs as far as the connector uses them.
type fakeDrive struct {
	mu       sync.Mutex
	version  int
	files    map[string]*ffile // id → file
	subjects map[string]string // path prefix → subject last used
	throttle int               // 403 rateLimitExceeded answers to give first
	grants   []map[string]any
}

type ffile struct {
	drive, owner, name, mime string
	data                     []byte
	perms                    []map[string]any
	modified                 time.Time
	removed                  bool
	version                  int
}

func (f *fakeDrive) change(id string, fn func(*ffile)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version++
	fl := f.files[id]
	if fl == nil {
		fl = &ffile{}
		f.files[id] = fl
	}
	fn(fl)
	fl.version = f.version
}

func (f *fakeDrive) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	subject := r.Header.Get("X-Test-Subject")
	if f.throttle > 0 {
		f.throttle--
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"errors":[{"reason":"userRateLimitExceeded"}],"code":403}}`))
		return
	}
	q := r.URL.Query()
	js := func(v any) { w.Header().Set("Content-Type", "application/json"); _ = json.NewEncoder(w).Encode(v) }
	// Which files this caller sees: a shared drive (admin), or the files the impersonated user owns.
	visible := func(id string, fl *ffile) bool {
		if d := q.Get("driveId"); d != "" {
			return fl.drive == d
		}
		return fl.drive == "" && fl.owner == subject
	}
	meta := func(id string, fl *ffile) map[string]any {
		m := map[string]any{"id": id, "name": fl.name, "mimeType": fl.mime, "modifiedTime": fl.modified.Format(time.RFC3339Nano), "trashed": false,
			"ownedByMe": fl.owner == subject}
		if !strings.HasPrefix(fl.mime, "application/vnd.google-apps.") {
			m["md5Checksum"] = fmt.Sprintf("%x", fl.data)
			m["size"] = strconv.Itoa(len(fl.data))
		}
		return m
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case r.URL.Path == "/drive/v3/drives":
		js(map[string]any{"drives": []any{map[string]any{"id": "sd-1", "name": "Divisi Kredit"}}})
	case r.URL.Path == "/admin/directory/v1/users":
		js(map[string]any{"users": []any{map[string]any{"primaryEmail": "ani@bankmega.com"}, map[string]any{"primaryEmail": "eks@bankmega.com", "suspended": true}}})
	case r.URL.Path == "/drive/v3/changes/startPageToken":
		js(map[string]any{"startPageToken": strconv.Itoa(f.version)})
	case r.URL.Path == "/drive/v3/files":
		var ids []string
		for id, fl := range f.files {
			if !fl.removed && visible(id, fl) {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		start, _ := strconv.Atoi(q.Get("pageToken"))
		end := min(start+2, len(ids))
		var out []any
		for _, id := range ids[min(start, len(ids)):end] {
			out = append(out, meta(id, f.files[id]))
		}
		res := map[string]any{"files": out}
		if end < len(ids) {
			res["nextPageToken"] = strconv.Itoa(end)
		}
		js(res)
	case r.URL.Path == "/drive/v3/changes":
		since, _ := strconv.Atoi(q.Get("pageToken"))
		var ids []string
		for id, fl := range f.files {
			if fl.version > since && (q.Get("driveId") == "" || fl.drive == q.Get("driveId")) {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		var out []any
		for _, id := range ids {
			fl := f.files[id]
			if fl.removed {
				out = append(out, map[string]any{"fileId": id, "removed": true})
			} else if q.Get("driveId") != "" || fl.drive == "" {
				out = append(out, map[string]any{"fileId": id, "file": meta(id, fl)})
			}
		}
		js(map[string]any{"changes": out, "newStartPageToken": strconv.Itoa(f.version)})
	case len(parts) >= 4 && parts[0] == "drive" && parts[2] == "files":
		fl := f.files[parts[3]]
		if fl == nil || fl.removed {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		f.subjects["file:"+parts[3]] = subject
		switch {
		case len(parts) == 5 && parts[4] == "permissions":
			js(map[string]any{"permissions": fl.perms})
		case len(parts) == 5 && parts[4] == "export" && q.Get("mimeType") == "text/plain":
			_, _ = w.Write([]byte("export: " + string(fl.data)))
		case len(parts) == 4 && q.Get("alt") == "media":
			_, _ = w.Write(fl.data)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	case r.URL.Path == "/admin/reports/v1/activity/users/all/applications/token":
		js(map[string]any{"items": f.grants})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type subjectRT struct{ subject string }

func (s subjectRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Test-Subject", s.subject)
	return http.DefaultTransport.RoundTrip(r)
}

func setup(t *testing.T) (*fakeDrive, *Drive, *[]time.Duration) {
	f := &fakeDrive{files: map[string]*ffile{}, subjects: map[string]string{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	var waits []time.Duration
	d := &Drive{BaseURL: srv.URL, Admin: "scanner@bankmega.com", Domains: []string{"bankmega.com"},
		Client:  func(subject string) *http.Client { return &http.Client{Transport: subjectRT{subject}} },
		Backoff: connector.Backoff{Retries: 3, Base: time.Second, Max: time.Minute, Sleep: func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }}}
	return f, d, &waits
}

// AC (ticket 32): the Google Drive connector against the SDK contract (a shared drive).
func TestContract(t *testing.T) {
	f, d, _ := setup(t)
	connectortest.Run(t, connectortest.Harness{
		Conn: d, Container: "drive:sd-1",
		Put: func(_ *testing.T, name string, b []byte) string {
			f.change("f-"+name, func(fl *ffile) {
				fl.drive, fl.name, fl.mime, fl.data, fl.modified, fl.removed = "sd-1", name, "text/plain", b, time.Now(), false
			})
			return "f-" + name
		},
		Delete: func(_ *testing.T, id string) { f.change(id, func(fl *ffile) { fl.removed = true }) },
		Share: func(_ *testing.T, id string) {
			f.change(id, func(fl *ffile) { fl.perms = []map[string]any{{"type": "anyone", "role": "reader"}} })
		},
		SharingInFeed: true,
	})
}

func TestMyDriveAndPermissions(t *testing.T) {
	f, d, waits := setup(t)
	f.change("doc-1", func(fl *ffile) {
		fl.owner, fl.name, fl.mime, fl.data, fl.modified = "ani@bankmega.com", "Rencana", "application/vnd.google-apps.document", []byte("NIK 3201011505900001"), time.Now()
		fl.perms = []map[string]any{
			{"type": "user", "role": "owner", "emailAddress": "ani@bankmega.com"},
			{"type": "user", "role": "writer", "emailAddress": "partner@konsultan.co.id"},
			{"type": "domain", "role": "reader", "domain": "bankmega.com"},
			{"type": "domain", "role": "reader", "domain": "vendor.com"},
			{"type": "group", "role": "reader", "emailAddress": "kredit@bankmega.com"},
		}
	})
	f.change("shared-in", func(fl *ffile) {
		fl.owner, fl.name, fl.mime, fl.data = "budi@bankmega.com", "x", "text/plain", []byte("x")
	})

	cs, err := d.Containers(context.Background())
	if err != nil || len(cs) != 2 || cs[1] != (connector.Container{ID: "user:ani@bankmega.com", Name: "ani@bankmega.com", Kind: "gdrive_mydrive"}) {
		t.Fatalf("containers %+v %v (suspended users excluded)", cs, err)
	}
	f.throttle = 2 // Google's quota answer is a 403 with a rate-limit reason
	p, err := d.Items(context.Background(), cs[1], "")
	if err != nil || len(p.Items) != 1 || p.Items[0].ID != "doc-1" || !strings.HasPrefix(p.Items[0].ContentTag, "m") {
		t.Fatalf("my drive: %+v %v", p, err)
	}
	if !slices.Equal(*waits, []time.Duration{time.Second, 2 * time.Second}) {
		t.Errorf("backoff on 403 rateLimitExceeded: %v", *waits)
	}
	// Google-native documents are exported as text, read as their owner.
	b, err := d.Get(context.Background(), p.Items[0], 1<<20)
	if err != nil || string(b) != "export: NIK 3201011505900001" || f.subjects["file:doc-1"] != "ani@bankmega.com" {
		t.Errorf("export: %q %v as %s", b, err, f.subjects["file:doc-1"])
	}
	acl, _ := d.ACL(context.Background(), p.Items[0])
	want := []connector.Grant{
		{Kind: "user", Ref: "ani@bankmega.com", Role: "owner"},
		{Kind: "user", Ref: "partner@konsultan.co.id", Role: "write", External: true},
		{Kind: "org_link", Ref: "bankmega.com", Role: "read"},
		{Kind: "specific_link", Ref: "vendor.com", Role: "read", External: true},
		{Kind: "group", Ref: "kredit@bankmega.com", Role: "read"},
	}
	if !slices.Equal(acl, want) {
		t.Errorf("acl:\n got %+v\nwant %+v", acl, want)
	}
}

func TestOAuthGrants(t *testing.T) {
	f, d, _ := setup(t)
	param := func(n, v string) map[string]any { return map[string]any{"name": n, "value": v} }
	f.grants = append(f.grants, map[string]any{"id": map[string]any{"time": "2026-10-03T10:00:00Z"}, "actor": map[string]any{"email": "Ani@bankmega.com"},
		"events": []any{map[string]any{"name": "authorize", "parameters": []any{param("client_id", "123.apps.googleusercontent.com"), param("app_name", "ChatGPT"),
			map[string]any{"name": "scope", "multiValue": []string{"https://www.googleapis.com/auth/drive.readonly"}}}}}})
	gs, err := d.OAuthGrants(context.Background(), time.Now().Add(-time.Hour))
	if err != nil || len(gs) != 1 || gs[0].AppName != "ChatGPT" || gs[0].User != "ani@bankmega.com" || gs[0].Scopes[0] != "https://www.googleapis.com/auth/drive.readonly" {
		t.Errorf("grants %+v %v", gs, err)
	}
}
