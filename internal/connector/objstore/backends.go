package objstore

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
)

const listPage = 1000

// --- S3-compatible: MinIO, AWS S3, GCS (XML API with HMAC keys) ---

// S3 is the minio-go backend. kind names what it fronts (s3 or gcs). Writer (credentials allowed to copy and
// delete) is used only to quarantine; nil = none.
type S3 struct {
	Client *minio.Client
	Writer *minio.Client
	kind   string
}

// Move copies the object (server side) and deletes the original.
func (s *S3) Move(ctx context.Context, srcBucket, srcKey, dstBucket, dstKey string) error {
	if s.Writer == nil {
		return fmt.Errorf("no remediation credentials for %s", s.kind)
	}
	if _, err := s.Writer.CopyObject(ctx, minio.CopyDestOptions{Bucket: dstBucket, Object: dstKey}, minio.CopySrcOptions{Bucket: srcBucket, Object: srcKey}); err != nil {
		return fmt.Errorf("copy to quarantine: %w", err)
	}
	return s.Writer.RemoveObject(ctx, srcBucket, srcKey, minio.RemoveObjectOptions{})
}

func NewS3(c *minio.Client, kind string) *S3 { return &S3{Client: c, kind: kind} }

func (s *S3) Kind() string { return s.kind }

func (s *S3) Buckets(ctx context.Context) ([]string, error) {
	bs, err := s.Client.ListBuckets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = b.Name
	}
	return out, nil
}

func (s *S3) List(ctx context.Context, bucket, marker string) ([]Object, string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // stop the lister after one page
	var out []Object
	for o := range s.Client.ListObjects(ctx, bucket, minio.ListObjectsOptions{Recursive: true, StartAfter: marker, MaxKeys: listPage}) {
		if o.Err != nil {
			return nil, "", o.Err
		}
		out = append(out, Object{Key: o.Key, ETag: normETag(o.ETag), Size: o.Size, Modified: o.LastModified})
		if len(out) == listPage {
			return out, o.Key, nil
		}
	}
	return out, "", nil
}

func (s *S3) Get(ctx context.Context, bucket, key string, maxBytes int64) ([]byte, error) {
	o, err := s.Client.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = o.Close() }()
	b, err := io.ReadAll(io.LimitReader(o, maxBytes+1))
	if err == nil && int64(len(b)) > maxBytes {
		err = fmt.Errorf("object exceeds %d bytes", maxBytes)
	}
	return b, err
}

// Public: a bucket policy that lets anyone (Principal "*") read objects. GCS has no bucket policies on the XML
// API: its public access (allUsers IAM) is not visible here and reads as not public. ponytail.
func (s *S3) Public(ctx context.Context, bucket string) (bool, error) {
	pol, err := s.Client.GetBucketPolicy(ctx, bucket)
	if err != nil {
		var er minio.ErrorResponse
		if errors.As(err, &er) && (er.Code == "NoSuchBucketPolicy" || er.Code == "NotImplemented") || s.kind == "gcs" {
			return false, nil
		}
		return false, err
	}
	return policyPublic(pol), nil
}

func policyPublic(pol string) bool {
	if pol == "" {
		return false
	}
	var doc struct {
		Statement []struct {
			Effect    string          `json:"Effect"`
			Principal json.RawMessage `json:"Principal"`
			Action    json.RawMessage `json:"Action"`
		} `json:"Statement"`
	}
	if json.Unmarshal([]byte(pol), &doc) != nil {
		return false
	}
	list := func(raw json.RawMessage) []string {
		var one string
		if json.Unmarshal(raw, &one) == nil {
			return []string{one}
		}
		var many []string
		_ = json.Unmarshal(raw, &many)
		return many
	}
	for _, st := range doc.Statement {
		if st.Effect != "Allow" {
			continue
		}
		anyone := string(st.Principal) == `"*"`
		var p struct {
			AWS json.RawMessage `json:"AWS"`
		}
		if json.Unmarshal(st.Principal, &p) == nil && p.AWS != nil {
			anyone = anyone || containsString(list(p.AWS), "*")
		}
		if !anyone {
			continue
		}
		for _, a := range list(st.Action) {
			if a == "s3:GetObject" || a == "s3:*" || a == "*" {
				return true
			}
		}
	}
	return false
}

// --- Azure Blob (REST with an account SAS: list + read) ---

// Azure talks to https://<account>.blob.core.windows.net (or an emulator) with a SAS query string.
type Azure struct {
	Endpoint string // e.g. https://bankdata.blob.core.windows.net
	SAS      string // account SAS (sp=rl, srt=sco), without the leading '?'
	HTTP     *http.Client
}

func (a *Azure) Kind() string { return "azure" }

func (a *Azure) get(ctx context.Context, path string, q url.Values) (*http.Response, error) {
	sas, err := url.ParseQuery(a.SAS)
	if err != nil {
		return nil, fmt.Errorf("SAS: %w", err)
	}
	for k, v := range q {
		sas[k] = v
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(a.Endpoint, "/")+path+"?"+sas.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-ms-version", "2023-11-03")
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("azure %d: %s", resp.StatusCode, path)
	}
	return resp, nil
}

type azContainers struct {
	Containers []struct {
		Name       string `xml:"Name"`
		Properties struct {
			PublicAccess string `xml:"PublicAccess"`
		} `xml:"Properties"`
	} `xml:"Containers>Container"`
	NextMarker string `xml:"NextMarker"`
}

func (a *Azure) containers(ctx context.Context) (azContainers, error) {
	var all azContainers
	marker := ""
	for {
		q := url.Values{"comp": {"list"}}
		if marker != "" {
			q.Set("marker", marker)
		}
		resp, err := a.get(ctx, "/", q)
		if err != nil {
			return all, err
		}
		var page azContainers
		err = xml.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&page)
		_ = resp.Body.Close()
		if err != nil {
			return all, err
		}
		all.Containers = append(all.Containers, page.Containers...)
		if marker = page.NextMarker; marker == "" {
			return all, nil
		}
	}
}

func (a *Azure) Buckets(ctx context.Context) ([]string, error) {
	cs, err := a.containers(ctx)
	var out []string
	for _, c := range cs.Containers {
		out = append(out, c.Name)
	}
	return out, err
}

func (a *Azure) List(ctx context.Context, container, marker string) ([]Object, string, error) {
	q := url.Values{"restype": {"container"}, "comp": {"list"}, "maxresults": {fmt.Sprint(listPage)}}
	if marker != "" {
		q.Set("marker", marker)
	}
	resp, err := a.get(ctx, "/"+url.PathEscape(container), q)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var page struct {
		Blobs []struct {
			Name       string `xml:"Name"`
			Properties struct {
				ETag          string `xml:"Etag"`
				ContentLength int64  `xml:"Content-Length"`
				LastModified  string `xml:"Last-Modified"`
			} `xml:"Properties"`
		} `xml:"Blobs>Blob"`
		NextMarker string `xml:"NextMarker"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&page); err != nil {
		return nil, "", err
	}
	var out []Object
	for _, b := range page.Blobs {
		mod, _ := time.Parse(time.RFC1123, b.Properties.LastModified)
		out = append(out, Object{Key: b.Name, ETag: normETag(b.Properties.ETag), Size: b.Properties.ContentLength, Modified: mod})
	}
	return out, page.NextMarker, nil
}

func (a *Azure) Get(ctx context.Context, container, key string, maxBytes int64) ([]byte, error) {
	resp, err := a.get(ctx, "/"+url.PathEscape(container)+"/"+(&url.URL{Path: key}).EscapedPath(), nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err == nil && int64(len(b)) > maxBytes {
		err = fmt.Errorf("blob exceeds %d bytes", maxBytes)
	}
	return b, err
}

// Public: the container's public access level is blob or container (anonymous reads).
func (a *Azure) Public(ctx context.Context, container string) (bool, error) {
	cs, err := a.containers(ctx)
	if err != nil {
		return false, err
	}
	for _, c := range cs.Containers {
		if c.Name == container {
			return c.Properties.PublicAccess == "blob" || c.Properties.PublicAccess == "container", nil
		}
	}
	return false, fmt.Errorf("container %s not found", container)
}
