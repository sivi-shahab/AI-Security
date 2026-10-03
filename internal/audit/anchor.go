package audit

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/minio/minio-go/v7"
)

// WIB is the bank's day boundary for anchors. Fixed offset: Indonesia has no DST and distroless has no tzdata.
var WIB = time.FixedZone("WIB", 7*3600)

// MinRetentionYears is the floor from spec §10.2; the bank may configure longer, never shorter.
const MinRetentionYears = 5

// Anchor records the chain head at the end of a WIB day, signed by the audit anchor key (KMS/HSM in production).
type Anchor struct {
	Day      string `json:"day"` // YYYY-MM-DD, WIB
	LastSeq  int64  `json:"last_seq"`
	LastHash string `json:"last_hash"`
	KeyID    string `json:"key_id"`
	Sig      string `json:"sig,omitempty"` // base64 ASN.1 ECDSA over SHA-256 of the anchor without sig
}

// DayBounds returns [start, end) of a WIB day "YYYY-MM-DD".
func DayBounds(day string) (time.Time, time.Time, error) {
	start, err := time.ParseInLocation(time.DateOnly, day, WIB)
	return start, start.AddDate(0, 0, 1), err
}

func (a Anchor) digest() []byte {
	a.Sig = ""
	b, _ := json.Marshal(a)
	d := sha256.Sum256(b)
	return d[:]
}

// Sign fills KeyID and Sig. signer is any crypto.Signer: a file key now, a PKCS#11/KMS handle later.
func (a *Anchor) Sign(signer crypto.Signer, keyID string) error {
	a.KeyID = keyID
	sig, err := signer.Sign(rand.Reader, a.digest(), crypto.SHA256)
	a.Sig = base64.StdEncoding.EncodeToString(sig)
	return err
}

// ponytail: ECDSA only; add RSA when the bank HSM key turns out to be RSA.
func (a Anchor) VerifySig(pub *ecdsa.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(a.Sig)
	if err != nil || !ecdsa.VerifyASN1(pub, a.digest(), sig) {
		return fmt.Errorf("anchor %s: invalid signature", a.Day)
	}
	return nil
}

func objectKey(day string) string { return "audit-anchors/" + day + ".json" }

// Put stores the anchor under COMPLIANCE object lock until retentionYears calendar years after the day ends. Writing an anchor that
// already exists is a no-op when it records the same head and an error otherwise: history must not be rewritten.
func Put(ctx context.Context, s3 *minio.Client, bucket string, a Anchor, retentionYears int) error {
	if retentionYears < MinRetentionYears {
		return fmt.Errorf("anchor retention %d years is below the %d-year minimum", retentionYears, MinRetentionYears)
	}
	if old, err := Get(ctx, s3, bucket, a.Day); err == nil {
		if old.LastSeq != a.LastSeq || old.LastHash != a.LastHash {
			return fmt.Errorf("anchor %s already exists with a different head (seq %d): chain rewritten?", a.Day, old.LastSeq)
		}
		return nil
	} else if !isNotFound(err) {
		return err
	}
	_, end, err := DayBounds(a.Day)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(a)
	_, err = s3.PutObject(ctx, bucket, objectKey(a.Day), bytes.NewReader(body), int64(len(body)), minio.PutObjectOptions{
		ContentType:     "application/json",
		Mode:            minio.Compliance,
		RetainUntilDate: end.AddDate(retentionYears, 0, 0),
	})
	return err
}

// Get reads a stored anchor.
func Get(ctx context.Context, s3 *minio.Client, bucket, day string) (Anchor, error) {
	var a Anchor
	obj, err := s3.GetObject(ctx, bucket, objectKey(day), minio.GetObjectOptions{})
	if err != nil {
		return a, err
	}
	defer func() { _ = obj.Close() }()
	return a, json.NewDecoder(obj).Decode(&a)
}

// ErrNoAnchor marks a day that should have been anchored but was not.
var ErrNoAnchor = errors.New("no anchor")

func isNotFound(err error) bool {
	return minio.ToErrorResponse(err).Code == minio.NoSuchKey
}
