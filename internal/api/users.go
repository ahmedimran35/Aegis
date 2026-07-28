package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/user/waf/internal/audit"
	"github.com/user/waf/internal/auth"
	"golang.org/x/crypto/bcrypt"
)

// UserHandler handles user management endpoints.
type UserHandler struct {
	pool  *pgxpool.Pool
	audit *audit.Logger
}

// NewUserHandler creates a new user handler.
func NewUserHandler(pool *pgxpool.Pool, auditLog *audit.Logger) *UserHandler {
	return &UserHandler{pool: pool, audit: auditLog}
}

var validRoles = map[string]bool{
	"viewer":  true,
	"analyst": true,
	"editor":  true,
	"admin":   true,
}

// List handles GET /api/v1/users
func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rows, err := h.pool.Query(ctx,
		`SELECT id, username, role, created_at::text FROM users ORDER BY created_at DESC`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "failed to query users")
		return
	}
	defer rows.Close()

	type userRow struct {
		ID        int    `json:"id"`
		Username  string `json:"username"`
		Role      string `json:"role"`
		CreatedAt string `json:"created_at"`
	}
	var users []userRow
	for rows.Next() {
		var u userRow
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt); err != nil {
			continue
		}
		users = append(users, u)
	}
	if users == nil {
		users = []userRow{}
	}
	RespondJSON(w, http.StatusOK, users)
}

// Create handles POST /api/v1/users
func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.Username == "" || req.Password == "" {
		RespondError(w, http.StatusBadRequest, "MISSING_FIELDS", "username and password required")
		return
	}
	if err := validatePassword(req.Password); err != nil {
		RespondError(w, http.StatusBadRequest, "WEAK_PASSWORD", err.Error())
		return
	}
	if req.Role == "" {
		req.Role = "viewer"
	}
	if !validRoles[req.Role] {
		RespondError(w, http.StatusBadRequest, "INVALID_ROLE", "role must be viewer, analyst, editor, or admin")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "HASH_ERROR", "failed to hash password")
		return
	}

	ctx := r.Context()
	var id int
	err = h.pool.QueryRow(ctx,
		`INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id`,
		req.Username, string(hash), req.Role).Scan(&id)
	if err != nil {
		RespondError(w, http.StatusConflict, "DUPLICATE", "username already exists")
		return
	}

	if h.audit != nil {
		var uid int
		var uname string
		if c := auth.ClaimsFromContext(r.Context()); c != nil {
			uid, uname = c.UserID, c.Username
		}
		h.audit.LogUserChange(uid, uname, "create", id, clientIP(r))
	}
	RespondJSON(w, http.StatusCreated, map[string]interface{}{
		"id":       id,
		"username": req.Username,
		"role":     req.Role,
	})
}

// UpdateRole handles PUT /api/v1/users/{id}/role
func (h *UserHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	// Prevent admin self-demotion
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		RespondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "authentication required")
		return
	}

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid user ID")
		return
	}

	// Block admin from changing their own role (prevents lockout)
	if claims.UserID == id {
		RespondError(w, http.StatusForbidden, "FORBIDDEN", "cannot change your own role")
		return
	}

	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if !validRoles[req.Role] {
		RespondError(w, http.StatusBadRequest, "INVALID_ROLE", "role must be viewer, analyst, editor, or admin")
		return
	}

	// M-47: block demotion of the last remaining admin.
	ctx := r.Context()
	if req.Role != "admin" {
		var currentRole string
		if err := h.pool.QueryRow(ctx, `SELECT role FROM users WHERE id = $1`, id).Scan(&currentRole); err == nil && currentRole == "admin" {
			var adminCount int
			if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&adminCount); err == nil && adminCount <= 1 {
				RespondError(w, http.StatusForbidden, "FORBIDDEN", "cannot demote the last admin")
				return
			}
		}
	}

	tag, execErr := h.pool.Exec(ctx,
		`UPDATE users SET role = $2, updated_at = NOW(), token_version = COALESCE(token_version, 0) + 1 WHERE id = $1`, id, req.Role)
	if execErr != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "failed to update role")
		return
	}
	if tag.RowsAffected() == 0 {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}

	if h.audit != nil {
		h.audit.LogUserChange(claims.UserID, claims.Username, "update_role", id, clientIP(r))
	}
	RespondJSON(w, http.StatusOK, map[string]interface{}{
		"id":   id,
		"role": req.Role,
	})
}

// ResetPassword handles POST /api/v1/users/{id}/reset-password (admin-only)
func (h *UserHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || claims.Role != "admin" {
		RespondError(w, http.StatusForbidden, "FORBIDDEN", "admin access required")
		return
	}

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid user ID")
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if err := validatePassword(req.Password); err != nil {
		RespondError(w, http.StatusBadRequest, "WEAK_PASSWORD", err.Error())
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 12)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "HASH_ERROR", "failed to hash password")
		return
	}

	ctx := r.Context()
	tag, execErr := h.pool.Exec(ctx,
		`UPDATE users SET password_hash = $2, must_change_password = true, updated_at = NOW(),
		 token_version = COALESCE(token_version, 0) + 1 WHERE id = $1`,
		id, string(hash))
	if execErr != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "failed to reset password")
		return
	}
	if tag.RowsAffected() == 0 {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}

	if h.audit != nil {
		h.audit.LogUserChange(claims.UserID, claims.Username, "reset_password", id, clientIP(r))
	}
	RespondJSON(w, http.StatusOK, map[string]string{"message": "password reset, user must change on next login"})
}

// DeleteUser handles DELETE /api/v1/users/{id} (admin-only)
func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || claims.Role != "admin" {
		RespondError(w, http.StatusForbidden, "FORBIDDEN", "admin access required")
		return
	}

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid user ID")
		return
	}

	// Prevent admin from deleting themselves
	if claims.UserID == id {
		RespondError(w, http.StatusForbidden, "FORBIDDEN", "cannot delete your own account")
		return
	}

	// M-47: prevent deleting the last admin so the system can't be
	// locked out of admin role by a single rogue admin action.
	ctx := r.Context()
	var targetRole string
	if err := h.pool.QueryRow(ctx, `SELECT role FROM users WHERE id = $1`, id).Scan(&targetRole); err == nil && targetRole == "admin" {
		var adminCount int
		if err := h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&adminCount); err == nil && adminCount <= 1 {
			RespondError(w, http.StatusForbidden, "FORBIDDEN", "cannot delete the last admin")
			return
		}
	}

	tag, execErr := h.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if execErr != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "failed to delete user")
		return
	}
	if tag.RowsAffected() == 0 {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}

	if h.audit != nil {
		h.audit.LogUserChange(claims.UserID, claims.Username, "delete", id, clientIP(r))
	}
	RespondJSON(w, http.StatusOK, map[string]string{"message": "user deleted"})
}
