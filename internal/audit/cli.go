package audit

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Main runs `audit anchor` / `audit verify` (control-plane subcommands, see cmd/control-plane) and returns the
// exit code. Config is env only: DATABASE_URL, AUDIT_S3_{ENDPOINT,BUCKET,ACCESS_KEY,SECRET_KEY,TLS},
// AUDIT_ANCHOR_KEY_FILE + AUDIT_ANCHOR_KEY_ID (anchor), AUDIT_ANCHOR_PUBKEY_FILE (verify), AUDIT_RETENTION_YEARS.
func Main(ctx context.Context, args []string, out io.Writer) int {
	if err := run(ctx, args, out, time.Now()); err != nil {
		_, _ = fmt.Fprintln(out, "FAIL:", err)
		return 1
	}
	return 0
}

func run(ctx context.Context, args []string, out io.Writer, now time.Time) error {
	if len(args) == 0 {
		return errors.New("usage: audit anchor --day YYYY-MM-DD|yesterday | audit verify --from YYYY-MM-DD --to YYYY-MM-DD")
	}
	fs := flag.NewFlagSet("audit "+args[0], flag.ContinueOnError)
	day := fs.String("day", "yesterday", "WIB day to anchor")
	from := fs.String("from", "", "first WIB day to verify")
	to := fs.String("to", "", "last WIB day to verify (inclusive)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	store, err := Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer store.Close()
	s3, err := newS3()
	if err != nil {
		return err
	}
	bucket := os.Getenv("AUDIT_S3_BUCKET")

	switch args[0] {
	case "anchor":
		if *day == "yesterday" {
			*day = now.In(WIB).AddDate(0, 0, -1).Format(time.DateOnly)
		}
		a, err := anchorDay(ctx, store, *day, now)
		if err != nil {
			return err
		}
		signer, err := loadSigner(os.Getenv("AUDIT_ANCHOR_KEY_FILE"))
		if err != nil {
			return err
		}
		if err := a.Sign(signer, os.Getenv("AUDIT_ANCHOR_KEY_ID")); err != nil {
			return err
		}
		years := MinRetentionYears
		if v := os.Getenv("AUDIT_RETENTION_YEARS"); v != "" {
			if years, err = strconv.Atoi(v); err != nil {
				return fmt.Errorf("AUDIT_RETENTION_YEARS: %w", err)
			}
		}
		if err := Put(ctx, s3, bucket, a, years); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "OK: anchored %s at seq %d %s\n", a.Day, a.LastSeq, a.LastHash)
		return err
	case "verify":
		pub, err := loadPub(os.Getenv("AUDIT_ANCHOR_PUBKEY_FILE"))
		if err != nil {
			return err
		}
		n, err := verifyDays(ctx, store, s3, bucket, pub, *from, *to, now)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "OK: %d entries and their anchors verify from %s to %s\n", n, *from, *to)
		return err
	}
	return fmt.Errorf("unknown audit command %q", args[0])
}

// anchorDay is the signed-to-be chain head at the end of a WIB day that has already ended.
func anchorDay(ctx context.Context, store *Store, day string, now time.Time) (Anchor, error) {
	_, end, err := DayBounds(day)
	if err != nil {
		return Anchor{}, err
	}
	if now.Before(end) {
		return Anchor{}, fmt.Errorf("day %s has not ended (WIB)", day)
	}
	seq, hash, err := store.Head(ctx, end)
	return Anchor{Day: day, LastSeq: seq, LastHash: hash}, err
}

// verifyDays checks the chain over [from, to] and, for every day that has ended, that its anchor exists, is
// signed by pub, and equals the head the database shows now (catches tail deletion or a rewritten chain).
func verifyDays(ctx context.Context, store *Store, s3 *minio.Client, bucket string, pub *ecdsa.PublicKey, from, to string, now time.Time) (int, error) {
	start, _, err := DayBounds(from)
	if err != nil {
		return 0, err
	}
	_, end, err := DayBounds(to)
	if err != nil {
		return 0, err
	}
	prevSeq, prevHash, entries, err := store.Range(ctx, start, end)
	if err != nil {
		return 0, err
	}
	if err := Verify(prevSeq, prevHash, entries); err != nil {
		return 0, err
	}
	for d := start; d.Before(end); d = d.AddDate(0, 0, 1) {
		day := d.Format(time.DateOnly)
		want, err := anchorDay(ctx, store, day, now)
		if err != nil {
			break // today: not anchored yet
		}
		got, err := Get(ctx, s3, bucket, day)
		if isNotFound(err) {
			return 0, fmt.Errorf("%w for %s", ErrNoAnchor, day)
		} else if err != nil {
			return 0, err
		}
		if err := got.VerifySig(pub); err != nil {
			return 0, err
		}
		if got.LastSeq != want.LastSeq || got.LastHash != want.LastHash {
			return 0, &BrokenError{got.LastSeq, fmt.Sprintf("anchor %s records head %d %s, database has %d %s",
				day, got.LastSeq, got.LastHash, want.LastSeq, want.LastHash)}
		}
	}
	return len(entries), nil
}

func newS3() (*minio.Client, error) {
	return minio.New(os.Getenv("AUDIT_S3_ENDPOINT"), &minio.Options{
		Creds:  credentials.NewStaticV4(os.Getenv("AUDIT_S3_ACCESS_KEY"), os.Getenv("AUDIT_S3_SECRET_KEY"), ""),
		Secure: os.Getenv("AUDIT_S3_TLS") != "false",
	})
}

// ponytail: PEM file key; swap for a PKCS#11 crypto.Signer when the bank HSM is wired (spec §10.1).
func loadSigner(path string) (crypto.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(raw)
	if b == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	if k, err := x509.ParseECPrivateKey(b.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: want an ECDSA key", path)
	}
	return s, nil
}

func loadPub(path string) (*ecdsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(raw)
	if b == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: want an ECDSA public key", path)
	}
	return pub, nil
}
