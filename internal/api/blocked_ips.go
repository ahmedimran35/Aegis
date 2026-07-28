package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/user/waf/internal/audit"
	"github.com/user/waf/internal/auth"
)

// BlockedIPHandler manages blocked IPs.
type BlockedIPHandler struct {
	pool  *pgxpool.Pool
	audit *audit.Logger
}

// NewBlockedIPHandler creates a new blocked IP handler.
func NewBlockedIPHandler(pool *pgxpool.Pool, auditLog *audit.Logger) *BlockedIPHandler {
	return &BlockedIPHandler{pool: pool, audit: auditLog}
}

type blockedIPRow struct {
	ID        int     `json:"id"`
	IPCIDR    string  `json:"ip_cidr"`
	Reason    string  `json:"reason"`
	Source    string  `json:"source"`
	ExpiresAt *string `json:"expires_at,omitempty"`
	CreatedAt string  `json:"created_at"`
}

type createBlockedIPRequest struct {
	IPCIDR    string `json:"ip_cidr"`
	Reason    string `json:"reason"`
	Source    string `json:"source"`
	ExpiresIn string `json:"expires_in"` // e.g., "24h", "7d"
}

// List handles GET /api/v1/blocked-ips
func (h *BlockedIPHandler) List(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "database not available")
		return
	}

	ctx := r.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT id, ip_cidr::text, COALESCE(reason, ''), COALESCE(source, 'manual'),
		 expires_at::text, created_at::text
		 FROM blocked_ips
		 WHERE expires_at IS NULL OR expires_at > NOW()
		 ORDER BY created_at DESC`)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}
	defer rows.Close()

	var items []blockedIPRow
	for rows.Next() {
		var item blockedIPRow
		if err := rows.Scan(&item.ID, &item.IPCIDR, &item.Reason, &item.Source, &item.ExpiresAt, &item.CreatedAt); err != nil {
			RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
			return
		}
		items = append(items, item)
	}

	if items == nil {
		items = []blockedIPRow{}
	}
	RespondJSON(w, http.StatusOK, items)
}

// Create handles POST /api/v1/blocked-ips
func (h *BlockedIPHandler) Create(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "database not available")
		return
	}

	var req createBlockedIPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	if req.IPCIDR == "" {
		RespondError(w, http.StatusBadRequest, "MISSING_FIELDS", "ip_cidr is required")
		return
	}

	// Validate IP/CIDR
	ip := net.ParseIP(req.IPCIDR)
	if ip == nil {
		if _, _, err := net.ParseCIDR(req.IPCIDR); err != nil {
			RespondError(w, http.StatusBadRequest, "INVALID_IP", "invalid IP or CIDR format")
			return
		}
	}

	if req.Source == "" {
		req.Source = "manual"
	}

	// Parse expiration
	var expiresAt *time.Time
	if req.ExpiresIn != "" {
		d, err := time.ParseDuration(req.ExpiresIn)
		if err != nil {
			RespondError(w, http.StatusBadRequest, "INVALID_DURATION", "invalid expires_in format (use e.g. 24h, 7d)")
			return
		}
		t := time.Now().Add(d)
		expiresAt = &t
	}

	ctx := r.Context()
	var item blockedIPRow
	err := h.pool.QueryRow(ctx,
		`INSERT INTO blocked_ips (ip_cidr, reason, source, expires_at)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, ip_cidr::text, COALESCE(reason, ''), COALESCE(source, 'manual'),
		 expires_at::text, created_at::text`,
		req.IPCIDR, req.Reason, req.Source, expiresAt,
	).Scan(&item.ID, &item.IPCIDR, &item.Reason, &item.Source, &item.ExpiresAt, &item.CreatedAt)

	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}

	if h.audit != nil {
		var uid int
		var uname string
		if c := auth.ClaimsFromContext(r.Context()); c != nil {
			uid, uname = c.UserID, c.Username
		}
		h.audit.Log(audit.Entry{UserID: uid, Username: uname, Action: "create", ResourceType: "blocked_ip", ResourceID: strconv.Itoa(item.ID), Details: map[string]string{"ip_cidr": item.IPCIDR, "reason": item.Reason}, IPAddress: clientIP(r)})
	}
	RespondJSON(w, http.StatusCreated, item)
}

// Delete handles DELETE /api/v1/blocked-ips/:id
func (h *BlockedIPHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if h.pool == nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", "database not available")
		return
	}

	id, err := strconv.Atoi(chi.URLParam(r, "id"))
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid ID")
		return
	}

	ctx := r.Context()
	tag, err := h.pool.Exec(ctx, `DELETE FROM blocked_ips WHERE id = $1`, id)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}
	if tag.RowsAffected() == 0 {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "blocked IP not found")
		return
	}

	if h.audit != nil {
		var uid int
		var uname string
		if c := auth.ClaimsFromContext(r.Context()); c != nil {
			uid, uname = c.UserID, c.Username
		}
		h.audit.Log(audit.Entry{UserID: uid, Username: uname, Action: "delete", ResourceType: "blocked_ip", ResourceID: strconv.Itoa(id), IPAddress: clientIP(r)})
	}
	RespondJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}
