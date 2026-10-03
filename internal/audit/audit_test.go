package audit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func chain(n int) []Entry {
	prev, out := Genesis, []Entry{}
	ts := time.Date(2026, 10, 3, 1, 2, 3, 456789000, time.UTC)
	for i := 1; i <= n; i++ {
		e := Entry{Seq: int64(i), TenantID: "t", TS: ts.Add(time.Duration(i) * time.Second), Actor: "admin@bank",
			Action: "policy.publish", Target: map[string]any{"policy": "p", "version": float64(i), "note": "<a&b>"}, PrevHash: prev}
		e.Hash = Hash(prev, e)
		prev, out = e.Hash, append(out, e)
	}
	return out
}

func brokenAt(t *testing.T, err error) int64 {
	t.Helper()
	var be *BrokenError
	if !errors.As(err, &be) {
		t.Fatalf("err = %v, want *BrokenError", err)
	}
	return be.Seq
}

func TestVerifyPinpointsTampering(t *testing.T) {
	if err := Verify(0, Genesis, chain(10)); err != nil {
		t.Fatalf("intact chain: %v", err)
	}

	edited := chain(10)
	edited[5].Target = map[string]any{"policy": "p", "version": float64(99)}
	if got := brokenAt(t, Verify(0, Genesis, edited)); got != 6 {
		t.Errorf("edited content: broken at %d, want 6", got)
	}

	rehashed := chain(10)
	rehashed[5].Actor = "attacker"
	rehashed[5].Hash = Hash(rehashed[5].PrevHash, rehashed[5])
	if got := brokenAt(t, Verify(0, Genesis, rehashed)); got != 7 {
		t.Errorf("edited + rehashed: broken at %d, want 7 (its successor no longer links)", got)
	}

	deleted := chain(10)
	deleted = append(deleted[:3:3], deleted[4:]...)
	if got := brokenAt(t, Verify(0, Genesis, deleted)); got != 4 {
		t.Errorf("deleted entry: broken at %d, want 4", got)
	}
}

func TestCanonicalIsStable(t *testing.T) {
	e := chain(1)[0]
	want := `{"action":"policy.publish","actor":"admin@bank","seq":1,"target":{"note":"<a&b>","policy":"p","version":1},` +
		`"tenant_id":"t","ts":"2026-10-03T01:02:04.456789Z"}`
	if got := string(Canonical(e)); got != want {
		t.Errorf("canonical\n got %s\nwant %s", got, want)
	}
}

func TestAnchorSignature(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a := Anchor{Day: "2026-10-02", LastSeq: 10, LastHash: chain(10)[9].Hash}
	if err := a.Sign(k, "audit-anchor-1"); err != nil {
		t.Fatal(err)
	}
	if err := a.VerifySig(&k.PublicKey); err != nil {
		t.Fatal(err)
	}
	a.LastSeq = 9
	if a.VerifySig(&k.PublicKey) == nil {
		t.Error("altered anchor still verifies")
	}
}

// Needs Postgres + S3 with object lock (CI services; locally see the ticket). Skipped only outside CI.
func TestStoreAndAnchorsIntegration(t *testing.T) {
	dbURL, s3URL := os.Getenv("AUDIT_TEST_DATABASE_URL"), os.Getenv("AUDIT_TEST_S3_ENDPOINT")
	if dbURL == "" || s3URL == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("AUDIT_TEST_DATABASE_URL / AUDIT_TEST_S3_ENDPOINT must be set in CI")
		}
		t.Skip("no test Postgres/S3")
	}
	ctx := context.Background()
	store, err := Open(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// Fresh schema per run: DROP is not blocked by the append-only triggers.
	if _, err := store.db.Exec(ctx, "DROP SCHEMA audit CASCADE"); err != nil {
		t.Fatal(err)
	}
	if store, err = Open(ctx, dbURL); err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	const tenant = "00000000-0000-0000-0000-000000000001"
	var last Entry
	for i := range 5 {
		if last, err = store.Append(ctx, tenant, "admin@bank", "policy.publish", map[string]any{"version": i, "big": int64(1) << 60}); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	today := now.In(WIB).Format(time.DateOnly)
	start, end, _ := DayBounds(today)
	prevSeq, prevHash, entries, err := store.Range(ctx, start, end)
	if err != nil || len(entries) != 5 {
		t.Fatalf("range: %d entries, err %v", len(entries), err)
	}
	if err := Verify(prevSeq, prevHash, entries); err != nil {
		t.Fatalf("fresh chain read back from Postgres: %v", err)
	}

	for _, sql := range []string{
		"UPDATE audit.audit_log SET actor = 'x' WHERE seq = 3",
		"DELETE FROM audit.audit_log WHERE seq = 5",
		"TRUNCATE audit.audit_log",
	} {
		if _, err := store.db.Exec(ctx, sql); err == nil {
			t.Errorf("%q succeeded on an append-only table", sql)
		}
	}

	// Anchor today as if it were tomorrow: it must record today's last entry.
	tomorrow := end.Add(time.Hour)
	a, err := anchorDay(ctx, store, today, tomorrow)
	if err != nil || a.LastSeq != last.Seq || a.LastHash != last.Hash {
		t.Fatalf("anchor %+v (err %v), want head %d %s", a, err, last.Seq, last.Hash)
	}
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := a.Sign(k, "test"); err != nil {
		t.Fatal(err)
	}

	s3, err := minio.New(s3URL, &minio.Options{Creds: credentials.NewStaticV4(os.Getenv("AUDIT_TEST_S3_ACCESS_KEY"), os.Getenv("AUDIT_TEST_S3_SECRET_KEY"), "")})
	if err != nil {
		t.Fatal(err)
	}
	bucket := "audit-test-" + now.Format("20060102150405")
	if err := s3.MakeBucket(ctx, bucket, minio.MakeBucketOptions{ObjectLocking: true}); err != nil {
		t.Fatal(err)
	}
	if err := Put(ctx, s3, bucket, a, 4); err == nil {
		t.Error("retention below 5 years accepted")
	}
	if err := Put(ctx, s3, bucket, a, MinRetentionYears); err != nil {
		t.Fatal(err)
	}
	if err := Put(ctx, s3, bucket, a, MinRetentionYears); err != nil {
		t.Errorf("re-anchoring the same head: %v", err)
	}
	forged := a
	forged.LastSeq--
	if err := Put(ctx, s3, bucket, forged, MinRetentionYears); err == nil {
		t.Error("overwrote an existing anchor with a different head")
	}
	info, err := s3.StatObject(ctx, bucket, objectKey(today), minio.StatObjectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	mode, until, err := s3.GetObjectRetention(ctx, bucket, objectKey(today), info.VersionID)
	if err != nil || mode == nil || *mode != minio.Compliance || until.Before(end.AddDate(5, 0, 0)) {
		t.Errorf("retention mode %v until %v (err %v), want COMPLIANCE until >= %v", mode, until, err, end.AddDate(5, 0, 0))
	}
	if err := s3.RemoveObject(ctx, bucket, objectKey(today), minio.RemoveObjectOptions{VersionID: info.VersionID}); err == nil {
		t.Error("deleted a locked anchor version")
	}

	if _, err := verifyDays(ctx, store, s3, bucket, &k.PublicKey, today, today, tomorrow); err != nil {
		t.Fatalf("verify intact day: %v", err)
	}
	// A superuser bypassing the trigger is exactly what verification must catch, at the edited row.
	if _, err := store.db.Exec(ctx, `ALTER TABLE audit.audit_log DISABLE TRIGGER audit_log_append_only;
		UPDATE audit.audit_log SET target = '{"version": 42}' WHERE seq = 3;
		ALTER TABLE audit.audit_log ENABLE TRIGGER audit_log_append_only`); err != nil {
		t.Fatal(err)
	}
	_, err = verifyDays(ctx, store, s3, bucket, &k.PublicKey, today, today, tomorrow)
	if got := brokenAt(t, err); got != 3 {
		t.Errorf("tampered row: broken at %d, want 3", got)
	}
	// Dropping the tail keeps the remaining chain valid; only the anchor notices.
	if _, err := store.db.Exec(ctx, `ALTER TABLE audit.audit_log DISABLE TRIGGER audit_log_append_only;
		UPDATE audit.audit_log SET target = '{"big": 1152921504606846976, "version": 2}' WHERE seq = 3;
		DELETE FROM audit.audit_log WHERE seq = 5;
		ALTER TABLE audit.audit_log ENABLE TRIGGER audit_log_append_only`); err != nil {
		t.Fatal(err)
	}
	_, err = verifyDays(ctx, store, s3, bucket, &k.PublicKey, today, today, tomorrow)
	if got := brokenAt(t, err); got != 5 {
		t.Errorf("deleted tail: err %v, want anchor mismatch at 5", err)
	}
}
