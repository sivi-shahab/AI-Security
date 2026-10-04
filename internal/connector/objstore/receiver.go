package objstore

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Receiver takes bucket event notifications at POST /events/{source} and queues them for the connector:
//
//	s3     S3 / MinIO event records ({"Records": [...]}): MinIO webhook target, S3 via SNS raw delivery
//	gcs    Cloud Storage notifications through a Pub/Sub push subscription
//	azure  Azure Event Grid (EventGridSchema), including its subscription validation handshake
//
// Senders authenticate with a bearer token or a token query parameter (Pub/Sub and Event Grid push URLs carry
// it there), compared by SHA-256.
type Receiver struct {
	DB          *pgxpool.Pool
	TokenSHA256 []byte
	Formats     map[string]string // source → s3 | gcs | azure
	Now         func() time.Time
}

type event struct {
	bucket, key, etag string
	size              int64
	deleted           bool
	at                time.Time
}

func (rc *Receiver) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /events/{source}", rc.serve)
}

func (rc *Receiver) serve(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	if h, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		tok = h
	}
	sum := sha256.Sum256([]byte(tok))
	if tok == "" || subtle.ConstantTimeCompare(sum[:], rc.TokenSHA256) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	source := r.PathValue("source")
	format, ok := rc.Formats[source]
	if !ok {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
	if err != nil {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var evs []event
	switch format {
	case "s3":
		evs, err = parseS3(body, rc.Now())
	case "gcs":
		evs, err = parseGCS(body, rc.Now())
	case "azure":
		var validation string
		evs, validation, err = parseAzure(body, rc.Now())
		if err == nil && validation != "" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"validationResponse": validation})
			return
		}
	}
	if err != nil {
		http.Error(w, "unreadable events: "+err.Error(), http.StatusBadRequest)
		return
	}
	for _, e := range evs {
		if _, err := rc.DB.Exec(r.Context(), "INSERT INTO data.object_events (source, bucket, key, etag, size, deleted, at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
			source, e.bucket, e.key, e.etag, e.size, e.deleted, e.at); err != nil {
			// Not acknowledged: every sender here retries, and the event is not lost.
			http.Error(w, "store failed", http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func normETag(s string) string { return strings.ToLower(strings.Trim(s, `"`)) }

func parseTime(s string, def time.Time) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	return def
}

// parseS3: AWS S3 / MinIO records. Keys arrive URL-encoded (form encoding: '+' is a space).
func parseS3(body []byte, now time.Time) ([]event, error) {
	var msg struct {
		Records []struct {
			EventName string `json:"eventName"`
			EventTime string `json:"eventTime"`
			S3        struct {
				Bucket struct {
					Name string `json:"name"`
				} `json:"bucket"`
				Object struct {
					Key  string `json:"key"`
					Size int64  `json:"size"`
					ETag string `json:"eTag"`
				} `json:"object"`
			} `json:"s3"`
		} `json:"Records"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, err
	}
	var out []event
	for _, rec := range msg.Records {
		key, err := url.QueryUnescape(rec.S3.Object.Key)
		if err != nil || rec.S3.Bucket.Name == "" || key == "" {
			return nil, fmt.Errorf("record without bucket or key")
		}
		name := strings.TrimPrefix(rec.EventName, "s3:")
		switch {
		case strings.HasPrefix(name, "ObjectCreated:"):
			out = append(out, event{rec.S3.Bucket.Name, key, normETag(rec.S3.Object.ETag), rec.S3.Object.Size, false, parseTime(rec.EventTime, now)})
		case strings.HasPrefix(name, "ObjectRemoved:"):
			out = append(out, event{rec.S3.Bucket.Name, key, "", 0, true, parseTime(rec.EventTime, now)})
		}
	}
	return out, nil
}

// parseGCS: a Pub/Sub push of a Cloud Storage notification (JSON_API_V1 payload). The listing goes through the
// S3-interoperable XML API, whose ETag is the hex MD5, so md5Hash (base64) is converted to match. The DELETE that
// accompanies an overwrite (overwrittenByGeneration) is not a deletion.
func parseGCS(body []byte, now time.Time) ([]event, error) {
	var push struct {
		Message struct {
			Attributes map[string]string `json:"attributes"`
			Data       string            `json:"data"`
		} `json:"message"`
	}
	if err := json.Unmarshal(body, &push); err != nil {
		return nil, err
	}
	a := push.Message.Attributes
	if a["bucketId"] == "" || a["objectId"] == "" {
		return nil, fmt.Errorf("notification without bucketId/objectId")
	}
	var obj struct {
		Size    string `json:"size"`
		MD5Hash string `json:"md5Hash"`
		ETag    string `json:"etag"`
		Updated string `json:"updated"`
	}
	if raw, err := base64.StdEncoding.DecodeString(push.Message.Data); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &obj)
	}
	etag := obj.ETag
	if md5, err := base64.StdEncoding.DecodeString(obj.MD5Hash); err == nil && len(md5) == 16 {
		etag = hex.EncodeToString(md5)
	}
	size, _ := strconv.ParseInt(obj.Size, 10, 64)
	at := parseTime(obj.Updated, now)
	switch a["eventType"] {
	case "OBJECT_FINALIZE", "OBJECT_METADATA_UPDATE":
		return []event{{a["bucketId"], a["objectId"], normETag(etag), size, false, at}}, nil
	case "OBJECT_DELETE", "OBJECT_ARCHIVE":
		if a["overwrittenByGeneration"] != "" {
			return nil, nil
		}
		return []event{{a["bucketId"], a["objectId"], "", 0, true, at}}, nil
	}
	return nil, nil
}

// parseAzure: Event Grid events for Blob Storage. A validation event returns its code for the handshake.
func parseAzure(body []byte, now time.Time) ([]event, string, error) {
	var evs []struct {
		EventType string          `json:"eventType"`
		Subject   string          `json:"subject"`
		EventTime string          `json:"eventTime"`
		Data      json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &evs); err != nil {
		return nil, "", err
	}
	var out []event
	for _, e := range evs {
		var d struct {
			ValidationCode string `json:"validationCode"`
			ETag           string `json:"eTag"`
			ContentLength  int64  `json:"contentLength"`
		}
		_ = json.Unmarshal(e.Data, &d)
		if e.EventType == "Microsoft.EventGrid.SubscriptionValidationEvent" {
			return nil, d.ValidationCode, nil
		}
		// subject: /blobServices/default/containers/<container>/blobs/<name>
		rest, ok := strings.CutPrefix(e.Subject, "/blobServices/default/containers/")
		container, blob, ok2 := strings.Cut(rest, "/blobs/")
		if !ok || !ok2 || container == "" || blob == "" {
			return nil, "", fmt.Errorf("unexpected subject %q", e.Subject)
		}
		switch e.EventType {
		case "Microsoft.Storage.BlobCreated":
			out = append(out, event{container, blob, normETag(d.ETag), d.ContentLength, false, parseTime(e.EventTime, now)})
		case "Microsoft.Storage.BlobDeleted":
			out = append(out, event{container, blob, "", 0, true, parseTime(e.EventTime, now)})
		}
	}
	return out, "", nil
}
