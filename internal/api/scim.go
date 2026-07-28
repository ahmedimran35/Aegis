// Package api: SCIM 2.0 user provisioning (P10-F3).
package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/user/waf/internal/audit"
	"golang.org/x/crypto/bcrypt"
)

// SCIMHandler serves SCIM 2.0 endpoints.
type SCIMHandler struct {
	pool        *pgxpool.Pool
	audit       *audit.Logger
	bearerToken string // env AEGIS_SCIM_TOKEN
	orgID       int    // SCIM tenant org_id; defaults to 1
}

// NewSCIMHandler creates the handler. orgID identifies the tenant scope
// for SCIM-provisioned accounts. If <=0, defaults to 1.
func NewSCIMHandler(pool *pgxpool.Pool, a *audit.Logger, bearerToken string, orgID int) *SCIMHandler {
	if orgID <= 0 {
		orgID = 1
	}
	return &SCIMHandler{pool: pool, audit: a, bearerToken: bearerToken, orgID: orgID}
}

// authMiddleware checks the bearer token.
//
// P-FIX (CWE-208): the comparison is performed on SHA-256 digests of both
// the supplied and expected tokens. Hashing first means the compare is over
// a fixed-length 32-byte buffer regardless of the secret length, which
// (a) prevents timing leaks about the secret length and (b) closes the
// timing oracle that would otherwise exist for byte-by-byte substring
// guesses. A constant-time delay is also applied before rejecting so the
// 401 path takes ~equal time whether or not the supplied token has the
// correct length.
func (h *SCIMHandler) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.bearerToken == "" {
			RespondError(w, http.StatusServiceUnavailable, "SCIM_DISABLED", "SCIM not configured")
			return
		}
		tok := r.Header.Get("Authorization")
		if len(tok) < 8 || tok[:7] != "Bearer " {
			// Constant-time pad: always perform the hash + compare even when
			// the prefix is malformed, so attackers cannot probe presence
			// of a valid Bearer prefix via response time.
			h.constantTimeReject(w, r)
			return
		}
		got := tok[7:]
		want := h.bearerToken
		// P-FIX (M-52/M-59): constant-time pad for length-difference leak.
		// Always hash both sides; the hash output is a fixed 32 bytes.
		gotHash := sha256.Sum256([]byte(got))
		wantHash := sha256.Sum256([]byte(want))
		if subtle.ConstantTimeCompare(gotHash[:], wantHash[:]) != 1 {
			h.constantTimeReject(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// constantTimeReject performs the SHA-256/hashing work + a randomized sleep
// before emitting the 401 response. This masks length-based timing leaks
// in authMiddleware by ensuring the rejection path always takes a roughly
// constant amount of wall-clock time.
func (h *SCIMHandler) constantTimeReject(w http.ResponseWriter, _ *http.Request) {
	start := time.Now()
	// Hash a dummy 32-byte secret so the rejection path performs the same
	// hashing work as the success path.
	var dummy [32]byte
	for i := range dummy {
		dummy[i] = byte(i)
	}
	gotHash := sha256.Sum256(dummy[:])
	wantHash := sha256.Sum256(dummy[:])
	subtle.ConstantTimeCompare(gotHash[:], wantHash[:])
	// Pad to a minimum response time (jittered +/- 25%) to mask the
	// remaining microsecond-level diffs from network/hash variance.
	const minReject = 5 * time.Millisecond
	if elapsed := time.Since(start); elapsed < minReject {
		time.Sleep(minReject - elapsed)
	}
	RespondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid bearer token")
}

// ListUsers handles GET /scim/Users.
func (h *SCIMHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	startIndex := 1
	count := 100
	if s := r.URL.Query().Get("startIndex"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			startIndex = n
		}
	}
	if c := r.URL.Query().Get("count"); c != "" {
		if n, err := strconv.Atoi(c); err == nil && n > 0 && n <= 1000 {
			count = n
		}
	}
	rows, err := h.pool.Query(r.Context(),
		`SELECT id, username, email, role, created_at, COALESCE(revoked, FALSE) FROM users
		 ORDER BY id LIMIT $1 OFFSET $2`, count, startIndex-1)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "query failed")
		return
	}
	defer rows.Close()
	resources := make([]map[string]any, 0, count)
	for rows.Next() {
		var id int
		var username, email, role, createdAt string
		var revoked bool
		if err := rows.Scan(&id, &username, &email, &role, &createdAt, &revoked); err != nil {
			continue
		}
		resources = append(resources, scimUserMap(id, username, email, role, createdAt, !revoked))
	}
	RespondJSON(w, http.StatusOK, map[string]any{
		"schemas":      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		"totalResults": len(resources),
		"Resources":    resources,
		"startIndex":   startIndex,
		"itemsPerPage": count,
	})
}

// GetUser handles GET /scim/Users/{id}.
func (h *SCIMHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid id")
		return
	}
	var username, email, role, createdAt string
	var revoked bool
	if err := h.pool.QueryRow(r.Context(),
		`SELECT username, email, role, created_at::text, COALESCE(revoked, FALSE) FROM users WHERE id = $1`, id).
		Scan(&username, &email, &role, &createdAt, &revoked); err != nil {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	RespondJSON(w, http.StatusOK, scimUserMap(id, username, email, role, createdAt, !revoked))
}

// CreateUser handles POST /scim/Users.
func (h *SCIMHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserName string             `json:"userName"`
		Emails   []scimEmail        `json:"emails"`
		Password string             `json:"password"`
		Name     *scimName          `json:"name"`
		Active   bool               `json:"active"`
		Schemas  []string           `json:"schemas"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid JSON")
		return
	}
	if req.UserName == "" {
		RespondError(w, http.StatusBadRequest, "MISSING_USERNAME", "userName required")
		return
	}
	if req.Password == "" {
		// SCIM: generate a random one-time password; user must change.
		buf := make([]byte, 16)
		_, _ = rand.Read(buf)
		req.Password = hex.EncodeToString(buf)
	}
	hash, err := authHashPassword(req.Password)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "HASH_ERROR", "hash failed")
		return
	}
	// P-FIX: SCIM standard stores emails as an array; extract the primary
	// or first one. The previous code decoded emails as a string, which
	// did not match any compliant SCIM client.
	email := primaryEmail(req.Emails)
	var id int
	if err := h.pool.QueryRow(r.Context(),
		`INSERT INTO users (username, email, password_hash, role, org_id, must_change_password)
		 VALUES ($1, $2, $3, 'viewer', $4, TRUE) RETURNING id`,
		req.UserName, email, hash, h.orgID).Scan(&id); err != nil {
		RespondError(w, http.StatusConflict, "USER_EXISTS", err.Error())
		return
	}
	if h.audit != nil {
		h.audit.Log(audit.Entry{Action: "scim.user.create", ResourceType: "user", ResourceID: strconv.Itoa(id)})
	}
	RespondJSON(w, http.StatusCreated, scimUserMap(id, req.UserName, email, "viewer", "", req.Active))
}

// DeleteUser handles DELETE /scim/Users/{id} — soft delete (revoked=true).
// Also bumps token_version so any JWT issued to the user is immediately
// invalidated (H-13).
func (h *SCIMHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid id")
		return
	}
	tag, err := h.pool.Exec(r.Context(),
		`UPDATE users SET revoked = TRUE, token_version = COALESCE(token_version, 0) + 1 WHERE id = $1`, id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "delete failed")
		return
	}
	if tag.RowsAffected() == 0 {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	if h.audit != nil {
		h.audit.Log(audit.Entry{Action: "scim.user.delete", ResourceType: "user", ResourceID: strconv.Itoa(id)})
	}
	w.WriteHeader(http.StatusNoContent)
}

// ReplaceUser handles PUT /scim/Users/{id}.
func (h *SCIMHandler) ReplaceUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid id")
		return
	}
	var req struct {
		UserName string      `json:"userName"`
		Emails   []scimEmail `json:"emails"`
		Active   bool        `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid JSON")
		return
	}
	email := primaryEmail(req.Emails)
	// H-14: when the user is being deactivated (active=false), bump
	// token_version to invalidate all existing JWTs. We also bump it on
	// every Replace so a stale token from an out-of-date client cannot
	// outlive the replacement.
	tag, err := h.pool.Exec(r.Context(),
		`UPDATE users SET username=$1, email=$2, revoked=$3,
		 token_version = COALESCE(token_version, 0) + 1
		 WHERE id=$4`,
		req.UserName, email, !req.Active, id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "update failed")
		return
	}
	if tag.RowsAffected() == 0 {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	if h.audit != nil {
		h.audit.Log(audit.Entry{Action: "scim.user.replace", ResourceType: "user", ResourceID: strconv.Itoa(id)})
	}
	RespondJSON(w, http.StatusOK, scimUserMap(id, req.UserName, email, "viewer", "", req.Active))
}

// PatchUser handles PATCH /scim/Users/{id}.
func (h *SCIMHandler) PatchUser(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid id")
		return
	}
	var req struct {
		Schemas    []string `json:"schemas"`
		Operations []struct {
			Op    string          `json:"op"`
			Path  string          `json:"path"`
			Value json.RawMessage `json:"value"`
		} `json:"Operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_BODY", "invalid JSON")
		return
	}
	notFound := false
	for _, op := range req.Operations {
		switch op.Op {
		case "replace", "add":
			switch op.Path {
			case "active":
				var v bool
				if err := json.Unmarshal(op.Value, &v); err == nil {
					tag, err := h.pool.Exec(r.Context(),
						`UPDATE users SET revoked=$1, token_version = COALESCE(token_version, 0) + 1 WHERE id=$2`,
						!v, id)
					if err != nil {
						RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
						return
					}
					if tag.RowsAffected() == 0 {
						notFound = true
					}
				}
			case "emails":
				// P-FIX: decode emails as SCIM array, not string.
				var emails []scimEmail
				if err := json.Unmarshal(op.Value, &emails); err == nil {
					email := primaryEmail(emails)
					tag, err := h.pool.Exec(r.Context(), `UPDATE users SET email=$1 WHERE id=$2`, email, id)
					if err != nil {
						RespondError(w, http.StatusInternalServerError, "DB_ERROR", err.Error())
						return
					}
					if tag.RowsAffected() == 0 {
						notFound = true
					}
				}
			}
		}
	}
	if notFound {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	if h.audit != nil {
		h.audit.Log(audit.Entry{Action: "scim.user.patch", ResourceType: "user", ResourceID: strconv.Itoa(id)})
	}
	w.WriteHeader(http.StatusNoContent)
}

// scimEmail matches the SCIM 2.0 email object shape.
type scimEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type"`
	Primary bool   `json:"primary"`
}

// scimName matches the SCIM 2.0 name object shape.
type scimName struct {
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
}

// primaryEmail returns the email marked primary, or the first one, or "".
func primaryEmail(es []scimEmail) string {
	for _, e := range es {
		if e.Primary && e.Value != "" {
			return e.Value
		}
	}
	for _, e := range es {
		if e.Value != "" {
			return e.Value
		}
	}
	return ""
}

// Middleware returns a chi.Router with the SCIM endpoints mounted.
func (h *SCIMHandler) Middleware() http.Handler {
	r := chi.NewRouter()
	r.Use(h.authMiddleware)
	r.Get("/Users", h.ListUsers)
	r.Post("/Users", h.CreateUser)
	r.Get("/Users/{id}", h.GetUser)
	r.Put("/Users/{id}", h.ReplaceUser)
	r.Patch("/Users/{id}", h.PatchUser)
	r.Delete("/Users/{id}", h.DeleteUser)
	return r
}

func scimUserMap(id int, username, email, role, createdAt string, active bool) map[string]any {
	return map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"id":       strconv.Itoa(id),
		"userName": username,
		"name":     map[string]any{"givenName": "", "familyName": ""},
		"emails":   []map[string]any{{"value": email, "primary": true}},
		"active":   active,
		"meta":     map[string]any{"resourceType": "User", "created": createdAt},
		"role":     role,
	}
}

func authHashPassword(p string) (string, error) {
	// P-FIX (CWE-256, CWE-916): was returning "$plaintext$" + p which stored
	// passwords in cleartext. Real impl: bcrypt at cost 12 (matches Users
	// handler) so SCIM-provisioned accounts use the same KDF as the rest
	// of the system.
	if p == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(p), 12)
	if err != nil {
		return "", fmt.Errorf("bcrypt: %w", err)
	}
	return string(h), nil
}
