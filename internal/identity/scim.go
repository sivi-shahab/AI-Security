package identity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// SCIM 2.0 (RFC 7643/7644) for the bank IdP's provisioning client: Users and Groups with create, get, filter
// (attr eq "value"), replace, PATCH and delete. That is the subset Entra ID and Okta use. Writes are audited as
// actor "scim", because group membership and deactivation change who holds which role.

const (
	schemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaList  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaError = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimActor   = "scim"
)

type scimError struct {
	status   int
	scimType string
	detail   string
}

func (e *scimError) Error() string { return e.detail }

func writeSCIM(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func writeSCIMError(w http.ResponseWriter, err error) {
	var se *scimError
	switch {
	case errors.As(err, &se):
	case errors.Is(err, ErrNotFound):
		se = &scimError{http.StatusNotFound, "", "resource not found"}
	case errors.Is(err, ErrConflict):
		se = &scimError{http.StatusConflict, "uniqueness", err.Error()}
	default:
		se = &scimError{http.StatusInternalServerError, "", "internal error"}
	}
	body := map[string]any{"schemas": []string{schemaError}, "status": strconv.Itoa(se.status), "detail": se.detail}
	if se.scimType != "" {
		body["scimType"] = se.scimType
	}
	writeSCIM(w, se.status, body)
}

// SCIMHandler serves /scim/v2/* behind a bearer token. tokenSHA256 is the SHA-256 of the token the IdP is
// configured with; the token itself is never held.
func (s *Store) SCIMHandler(tokenSHA256 []byte, baseURL string) http.Handler {
	mux := http.NewServeMux()
	h := func(pattern string, f func(*http.Request) (int, any, error)) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			status, v, err := f(r)
			if err != nil {
				writeSCIMError(w, err)
				return
			}
			writeSCIM(w, status, v)
		})
	}
	for _, kind := range []string{"Users", "Groups"} {
		h("POST /scim/v2/"+kind, func(r *http.Request) (int, any, error) {
			doc, err := readDoc(r)
			if err != nil {
				return 0, nil, err
			}
			res, err := s.scimCreate(r.Context(), kind, doc, baseURL)
			return http.StatusCreated, res, err
		})
		h("GET /scim/v2/"+kind, func(r *http.Request) (int, any, error) {
			res, err := s.scimList(r.Context(), kind, r.URL.Query().Get("filter"), baseURL)
			return http.StatusOK, res, err
		})
		h("GET /scim/v2/"+kind+"/{id}", func(r *http.Request) (int, any, error) {
			res, err := s.scimGet(r.Context(), s.db, kind, r.PathValue("id"), baseURL)
			return http.StatusOK, res, err
		})
		h("PUT /scim/v2/"+kind+"/{id}", func(r *http.Request) (int, any, error) {
			doc, err := readDoc(r)
			if err != nil {
				return 0, nil, err
			}
			res, err := s.scimUpdate(r.Context(), kind, r.PathValue("id"), baseURL, func(map[string]any) (map[string]any, error) { return doc, nil })
			return http.StatusOK, res, err
		})
		h("PATCH /scim/v2/"+kind+"/{id}", func(r *http.Request) (int, any, error) {
			var body struct {
				Operations []patchOp `json:"Operations"`
			}
			if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(&body); err != nil {
				return 0, nil, &scimError{http.StatusBadRequest, "invalidSyntax", "malformed PATCH body"}
			}
			res, err := s.scimUpdate(r.Context(), kind, r.PathValue("id"), baseURL, func(doc map[string]any) (map[string]any, error) {
				for _, op := range body.Operations {
					if err := op.apply(doc); err != nil {
						return nil, err
					}
				}
				return doc, nil
			})
			return http.StatusOK, res, err
		})
		h("DELETE /scim/v2/"+kind+"/{id}", func(r *http.Request) (int, any, error) {
			return http.StatusNoContent, nil, s.scimDelete(r.Context(), kind, r.PathValue("id"))
		})
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare(got[:], tokenSHA256) != 1 {
			writeSCIMError(w, &scimError{http.StatusUnauthorized, "", "invalid SCIM token"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func readDoc(r *http.Request) (map[string]any, error) {
	var doc map[string]any
	if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, &scimError{http.StatusBadRequest, "invalidSyntax", "malformed JSON"}
	}
	return doc, nil
}

// --- documents --------------------------------------------------------------------------------------------

// clean drops server-owned attributes and normalizes what lookups need. Members live in group_members, not doc.
func clean(kind string, doc map[string]any) (key string, active bool, members []string, err error) {
	delete(doc, "id")
	delete(doc, "meta")
	active = true
	if kind == "Users" {
		key, _ = doc["userName"].(string)
		if a, ok := doc["active"]; ok {
			active = truthy(a)
			doc["active"] = active
		}
	} else {
		key, _ = doc["displayName"].(string)
		if m, ok := doc["members"].([]any); ok {
			for _, x := range m {
				if v, ok := x.(map[string]any)["value"].(string); ok {
					members = append(members, v)
				}
			}
		}
		delete(doc, "members")
	}
	if strings.TrimSpace(key) == "" {
		return "", false, nil, &scimError{http.StatusBadRequest, "invalidValue", "userName/displayName is required"}
	}
	return key, active, members, nil
}

// truthy accepts SCIM booleans and the string forms some IdPs send ("False").
func truthy(v any) bool {
	switch v := v.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	}
	return false
}

func table(kind string) (tbl, keyCol, schema, resourceType string) {
	if kind == "Users" {
		return "identity.users", "user_name", schemaUser, "User"
	}
	return "identity.groups", "display_name", schemaGroup, "Group"
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func (s *Store) scimGet(ctx context.Context, q querier, kind, id, baseURL string) (map[string]any, error) {
	tbl, _, schema, rt := table(kind)
	var doc map[string]any
	var created, updated time.Time
	err := q.QueryRow(ctx, "SELECT doc, created_at, updated_at FROM "+tbl+" WHERE id::text = $1", id).Scan(&doc, &created, &updated)
	if err != nil {
		return nil, notFound(err)
	}
	doc["id"], doc["schemas"] = id, []string{schema}
	doc["meta"] = map[string]any{"resourceType": rt, "created": created, "lastModified": updated, "location": baseURL + "/scim/v2/" + kind + "/" + id}
	if kind == "Groups" {
		rows, err := q.Query(ctx, "SELECT m.user_id::text, u.user_name FROM identity.group_members m JOIN identity.users u ON u.id = m.user_id WHERE m.group_id = $1 ORDER BY u.user_name", id)
		if err != nil {
			return nil, err
		}
		members := []any{}
		for rows.Next() {
			var uid, name string
			if err := rows.Scan(&uid, &name); err != nil {
				return nil, err
			}
			members = append(members, map[string]any{"value": uid, "display": name})
		}
		doc["members"] = members
	}
	return doc, nil
}

var filterRe = regexp.MustCompile(`^\s*(userName|externalId|displayName)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$`)

func (s *Store) scimList(ctx context.Context, kind, filter, baseURL string) (map[string]any, error) {
	tbl, keyCol, _, _ := table(kind)
	where, args := "", []any{}
	if filter != "" {
		m := filterRe.FindStringSubmatch(filter)
		if m == nil {
			return nil, &scimError{http.StatusBadRequest, "invalidFilter", `supported: userName|externalId|displayName eq "value"`}
		}
		val := strings.ReplaceAll(m[2], `\"`, `"`)
		switch m[1] {
		case "externalId":
			where, args = " WHERE doc->>'externalId' = $1", []any{val}
		default:
			where, args = " WHERE lower("+keyCol+") = lower($1)", []any{val}
		}
	}
	rows, err := s.db.Query(ctx, "SELECT id::text FROM "+tbl+where+" ORDER BY created_at LIMIT 1000", args...)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	resources := []any{}
	for _, id := range ids {
		doc, err := s.scimGet(ctx, s.db, kind, id, baseURL)
		if err != nil {
			return nil, err
		}
		resources = append(resources, doc)
	}
	return map[string]any{"schemas": []string{schemaList}, "totalResults": len(resources), "startIndex": 1, "itemsPerPage": len(resources), "Resources": resources}, nil
}

func uniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func (s *Store) scimCreate(ctx context.Context, kind string, doc map[string]any, baseURL string) (map[string]any, error) {
	key, active, members, err := clean(kind, doc)
	if err != nil {
		return nil, err
	}
	tbl, keyCol, _, _ := table(kind)
	var res map[string]any
	err = s.inTx(ctx, scimActor, "identity."+strings.ToLower(strings.TrimSuffix(kind, "s"))+".create", func(tx pgx.Tx) (map[string]any, error) {
		var id string
		cols, vals, args := keyCol+", doc", "$1, $2", []any{key, doc}
		if kind == "Users" {
			cols, vals, args = cols+", active", vals+", $3", append(args, active)
		}
		if err := tx.QueryRow(ctx, "INSERT INTO "+tbl+" ("+cols+") VALUES ("+vals+") RETURNING id::text", args...).Scan(&id); err != nil {
			if uniqueViolation(err) {
				return nil, fmt.Errorf("%w: %s already exists", ErrConflict, key)
			}
			return nil, err
		}
		if err := setMembers(ctx, tx, id, members); err != nil {
			return nil, err
		}
		res, err = s.scimGet(ctx, tx, kind, id, baseURL)
		return map[string]any{"id": id, "name": key, "active": active, "members": members}, err
	})
	return res, err
}

// scimUpdate loads the resource (with members for groups), lets f produce the new document, and stores it.
// Audited with what changed in membership and activation, the parts that move permissions.
func (s *Store) scimUpdate(ctx context.Context, kind, id, baseURL string, f func(map[string]any) (map[string]any, error)) (map[string]any, error) {
	tbl, keyCol, _, _ := table(kind)
	var res map[string]any
	err := s.inTx(ctx, scimActor, "identity."+strings.ToLower(strings.TrimSuffix(kind, "s"))+".update", func(tx pgx.Tx) (map[string]any, error) {
		cur, err := s.scimGet(ctx, tx, kind, id, baseURL)
		if err != nil {
			return nil, err
		}
		before := memberSet(cur)
		wasActive := truthy(cur["active"])
		doc, err := f(cur)
		if err != nil {
			return nil, err
		}
		key, active, members, err := clean(kind, doc)
		if err != nil {
			return nil, err
		}
		delete(doc, "schemas")
		args := []any{id, key, doc}
		set := keyCol + " = $2, doc = $3, updated_at = now()"
		if kind == "Users" {
			set, args = set+", active = $4", append(args, active)
		}
		if _, err := tx.Exec(ctx, "UPDATE "+tbl+" SET "+set+" WHERE id = $1", args...); err != nil {
			if uniqueViolation(err) {
				return nil, fmt.Errorf("%w: %s already exists", ErrConflict, key)
			}
			return nil, err
		}
		target := map[string]any{"id": id, "name": key}
		if kind == "Groups" {
			if err := setMembers(ctx, tx, id, members); err != nil {
				return nil, err
			}
			added, removed := diff(before, members)
			target["members_added"], target["members_removed"] = added, removed
		} else if wasActive != active {
			target["active"] = active
		}
		res, err = s.scimGet(ctx, tx, kind, id, baseURL)
		return target, err
	})
	return res, err
}

func (s *Store) scimDelete(ctx context.Context, kind, id string) error {
	tbl, keyCol, _, _ := table(kind)
	return s.inTx(ctx, scimActor, "identity."+strings.ToLower(strings.TrimSuffix(kind, "s"))+".delete", func(tx pgx.Tx) (map[string]any, error) {
		var key string
		var bindings int
		// Count first: ON DELETE CASCADE removes the bindings, and the audit entry should say how many.
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM identity.role_bindings WHERE user_id::text = $1 OR group_id::text = $1", id).Scan(&bindings); err != nil {
			return nil, err
		}
		if err := tx.QueryRow(ctx, "DELETE FROM "+tbl+" WHERE id::text = $1 RETURNING "+keyCol, id).Scan(&key); err != nil {
			return nil, notFound(err)
		}
		return map[string]any{"id": id, "name": key, "bindings_removed": bindings}, nil
	})
}

func setMembers(ctx context.Context, tx pgx.Tx, groupID string, members []string) error {
	if _, err := tx.Exec(ctx, "DELETE FROM identity.group_members WHERE group_id = $1", groupID); err != nil {
		return err
	}
	for _, m := range members {
		tag, err := tx.Exec(ctx, "INSERT INTO identity.group_members (group_id, user_id) SELECT $1, id FROM identity.users WHERE id::text = $2 ON CONFLICT DO NOTHING", groupID, m)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var exists bool
			_ = tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM identity.users WHERE id::text = $1)", m).Scan(&exists)
			if !exists {
				return &scimError{http.StatusBadRequest, "invalidValue", "unknown member " + m}
			}
		}
	}
	return nil
}

func memberSet(doc map[string]any) []string {
	var out []string
	if m, ok := doc["members"].([]any); ok {
		for _, x := range m {
			if v, ok := x.(map[string]any)["value"].(string); ok {
				out = append(out, v)
			}
		}
	}
	return out
}

func diff(before, after []string) (added, removed []string) {
	added, removed = []string{}, []string{}
	for _, v := range after {
		if !slices.Contains(before, v) && !slices.Contains(added, v) {
			added = append(added, v)
		}
	}
	for _, v := range before {
		if !slices.Contains(after, v) {
			removed = append(removed, v)
		}
	}
	return added, removed
}

// --- PATCH ------------------------------------------------------------------------------------------------

type patchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

var memberFilterRe = regexp.MustCompile(`^members\[value eq "([^"]+)"\]$`)

func (op patchOp) apply(doc map[string]any) error {
	switch strings.ToLower(op.Op) {
	case "add", "replace":
		if op.Path == "" {
			obj, ok := op.Value.(map[string]any)
			if !ok {
				return &scimError{http.StatusBadRequest, "invalidValue", "add/replace without path needs an object"}
			}
			for k, v := range obj {
				cur, curOK := doc[k].(map[string]any)
				if add, ok := v.(map[string]any); ok && curOK { // e.g. the enterprise extension object: merge
					for ak, av := range add {
						cur[ak] = av
					}
					continue
				}
				if strings.Contains(k, ".") && !strings.HasPrefix(k, "urn:") {
					parent, leaf := walk(doc, k)
					parent[leaf] = v
					continue
				}
				doc[k] = v
			}
			return nil
		}
		if op.Path == "members" && strings.EqualFold(op.Op, "add") {
			list, _ := doc["members"].([]any)
			vals, _ := op.Value.([]any)
			doc["members"] = append(list, vals...)
			return nil
		}
		parent, leaf := walk(doc, op.Path)
		parent[leaf] = op.Value
		return nil
	case "remove":
		if m := memberFilterRe.FindStringSubmatch(op.Path); m != nil {
			return removeMembers(doc, []string{m[1]})
		}
		if op.Path == "members" {
			if vals, ok := op.Value.([]any); ok {
				var ids []string
				for _, v := range vals {
					if id, ok := v.(map[string]any)["value"].(string); ok {
						ids = append(ids, id)
					}
				}
				return removeMembers(doc, ids)
			}
			doc["members"] = []any{}
			return nil
		}
		if op.Path == "" {
			return &scimError{http.StatusBadRequest, "noTarget", "remove needs a path"}
		}
		parent, leaf := walk(doc, op.Path)
		delete(parent, leaf)
		return nil
	}
	return &scimError{http.StatusBadRequest, "invalidSyntax", "unknown op " + op.Op}
}

func removeMembers(doc map[string]any, ids []string) error {
	list, _ := doc["members"].([]any)
	kept := []any{}
	for _, x := range list {
		v, _ := x.(map[string]any)["value"].(string)
		drop := false
		for _, id := range ids {
			drop = drop || v == id
		}
		if !drop {
			kept = append(kept, x)
		}
	}
	doc["members"] = kept
	return nil
}

// walk resolves "name.givenName" or an extension path "urn:...:User:department" to (parent object, leaf key).
func walk(doc map[string]any, path string) (map[string]any, string) {
	var parts []string
	switch {
	case strings.HasPrefix(path, "urn:") && (strings.HasSuffix(path, ":User") || strings.HasSuffix(path, ":Group")):
		parts = []string{path} // the extension object itself
	case strings.HasPrefix(path, "urn:"):
		i := strings.LastIndex(path, ":")
		parts = []string{path[:i], path[i+1:]}
	default:
		parts = strings.Split(path, ".")
	}
	cur := doc
	for _, p := range parts[:len(parts)-1] {
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
	return cur, parts[len(parts)-1]
}
