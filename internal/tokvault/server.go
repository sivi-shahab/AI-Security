package tokvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
)

// Leader is the vault's active-passive role (spec §5.3): the replica holding a session advisory lock serves, the
// others answer 503 and are not ready, so the Service sends traffic to the active one and a client fails over to the
// next URL. When the active replica dies its connection closes, the lock frees, and a passive one takes it.
type Leader struct{ active atomic.Bool }

const lockKey = 0x746f6b76 // "tokv"

func (l *Leader) Active() bool { return l.active.Load() }

// Run competes for the lock until ctx ends, checking the held connection every interval.
func (l *Leader) Run(ctx context.Context, dbURL string, interval time.Duration, log *slog.Logger) {
	for ctx.Err() == nil {
		l.hold(ctx, dbURL, interval, log)
		l.active.Store(false)
		select {
		case <-ctx.Done():
		case <-time.After(interval):
		}
	}
}

func (l *Leader) hold(ctx context.Context, dbURL string, interval time.Duration, log *slog.Logger) {
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		log.Error("vault leader: connect", "err", err)
		return
	}
	defer func() { _ = conn.Close(context.Background()) }() // closing the session releases the lock
	for ctx.Err() == nil {
		if !l.active.Load() {
			var got bool
			if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", lockKey).Scan(&got); err != nil {
				return
			}
			if got {
				log.Info("vault is active")
				l.active.Store(true)
			}
		} else if _, err := conn.Exec(ctx, "SELECT 1"); err != nil {
			log.Error("vault leader: lost the lock connection", "err", err)
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(interval):
		}
	}
}

// TokenizeRequest is POST /tokenize.
type TokenizeRequest struct {
	Items      []Item `json:"items"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// MaxTTL caps what a caller may ask for.
const MaxTTL = 7 * 24 * time.Hour

// Routes serves the vault API to callers presenting a token whose SHA-256 is clientSHA256 (the AI gateway).
// Values cross this API in the clear inside the cluster: the PEP already has them, and §10.1 puts mTLS under it.
func (v *Vault) Routes(mux *http.ServeMux, l *Leader, clientSHA256 string) {
	want, _ := hex.DecodeString(clientSHA256)
	serve := func(handle func(r *http.Request) (any, error)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			got := sha256.Sum256([]byte(tok))
			switch {
			case len(want) != sha256.Size || tok == "" || subtle.ConstantTimeCompare(got[:], want) != 1:
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			case !l.Active():
				http.Error(w, "passive replica", http.StatusServiceUnavailable)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			out, err := handle(r)
			if err != nil {
				status := http.StatusInternalServerError
				if errors.Is(err, ErrClass) || errors.Is(err, ErrShort) || errors.Is(err, errBadRequest) {
					status = http.StatusBadRequest
				}
				http.Error(w, err.Error(), status) // errors name classes and positions, never values
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
		}
	}
	mux.HandleFunc("POST /tokenize", serve(func(r *http.Request) (any, error) {
		var req TokenizeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TTLSeconds <= 0 {
			return nil, errBadRequest
		}
		ts, err := v.Tokenize(r.Context(), req.Items, min(time.Duration(req.TTLSeconds)*time.Second, MaxTTL))
		return map[string]any{"tokens": ts}, err
	}))
	mux.HandleFunc("POST /detokenize", serve(func(r *http.Request) (any, error) {
		var req DetokenizeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.App == "" {
			return nil, errBadRequest
		}
		vs, err := v.Detokenize(r.Context(), req)
		return map[string]any{"values": vs}, err
	}))
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, _ *http.Request) {
		if !l.Active() {
			http.Error(w, "passive", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("active"))
	})
}

var errBadRequest = errors.New("bad request")

// Client calls the vault, trying each URL in turn: a passive replica (503) or one that is down sends it to the next.
type Client struct {
	URLs  []string
	Token string
	HTTP  *http.Client
}

func (c *Client) Tokenize(ctx context.Context, items []Item, ttl time.Duration) ([]string, error) {
	var out struct {
		Tokens []string `json:"tokens"`
	}
	err := c.post(ctx, "/tokenize", TokenizeRequest{Items: items, TTLSeconds: int(ttl.Seconds())}, &out)
	if err == nil && len(out.Tokens) != len(items) {
		err = errors.New("vault returned a short answer")
	}
	return out.Tokens, err
}

func (c *Client) Detokenize(ctx context.Context, req DetokenizeRequest) ([]*string, error) {
	var out struct {
		Values []*string `json:"values"`
	}
	err := c.post(ctx, "/detokenize", req, &out)
	if err == nil && len(out.Values) != len(req.Items) {
		err = errors.New("vault returned a short answer")
	}
	return out.Values, err
}

func (c *Client) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	var errs []error
	for _, u := range c.URLs {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(u, "/")+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.Token)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		switch resp.StatusCode {
		case http.StatusOK:
			err = json.NewDecoder(resp.Body).Decode(out)
			_ = resp.Body.Close()
			return err
		case http.StatusServiceUnavailable, http.StatusBadGateway:
			_ = resp.Body.Close()
			errs = append(errs, fmt.Errorf("%s: %d", u, resp.StatusCode))
			continue
		}
		_ = resp.Body.Close()
		return fmt.Errorf("vault %s: status %d", path, resp.StatusCode)
	}
	return fmt.Errorf("no active vault: %w", errors.Join(errs...))
}
