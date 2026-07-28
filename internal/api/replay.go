package api

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/user/waf/internal/replay"
)

// ReplayHandler handles request replay API endpoints.
type ReplayHandler struct {
	service *replay.Service
}

// NewReplayHandler creates a replay handler.
func NewReplayHandler(service *replay.Service) *ReplayHandler {
	return &ReplayHandler{service: service}
}

// List returns stored blocked requests.
func (h *ReplayHandler) List(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 50
	}

	requests, total, err := h.service.List(r.Context(), page, perPage)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}

	RespondJSONWithMeta(w, http.StatusOK, requests, &Meta{
		Page:    page,
		PerPage: perPage,
		Total:   total,
	})
}

// Get returns a single stored request.
func (h *ReplayHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid request ID")
		return
	}

	request, err := h.service.Get(r.Context(), id)
	if err != nil {
		RespondError(w, http.StatusNotFound, "NOT_FOUND", "request not found")
		return
	}

	RespondJSON(w, http.StatusOK, request)
}

// Replay sends a stored request to the upstream.
func (h *ReplayHandler) Replay(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid request ID")
		return
	}

	var body struct {
		TargetURL string `json:"target_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_JSON", "invalid request body")
		return
	}

	var pinnedIP string
	var hostname string
	if body.TargetURL != "" {
		parsed, err := url.Parse(body.TargetURL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			RespondError(w, http.StatusBadRequest, "INVALID_URL", "target_url must be a valid http/https URL")
			return
		}
		hostname = parsed.Hostname()
		if hostname == "" {
			RespondError(w, http.StatusBadRequest, "INVALID_URL", "target_url must have a valid host")
			return
		}
		ip := net.ParseIP(hostname)
		if ip == nil {
			ips, err := net.LookupIP(hostname)
			if err != nil || len(ips) == 0 {
				RespondError(w, http.StatusBadRequest, "INVALID_URL", "cannot resolve target host")
				return
			}
			for _, resolved := range ips {
				if isPrivateIP(resolved) {
					RespondError(w, http.StatusBadRequest, "BLOCKED_URL", "target_url cannot point to internal/private IP ranges")
					return
				}
			}
			ip = ips[0]
		} else if isPrivateIP(ip) {
			RespondError(w, http.StatusBadRequest, "BLOCKED_URL", "target_url cannot point to internal/private IP ranges")
			return
		}
		pinnedIP = ip.String()
	}

	result, err := h.service.Replay(r.Context(), id, body.TargetURL, pinnedIP, hostname)
	if err != nil {
		RespondError(w, http.StatusInternalServerError, "REPLAY_ERROR", safeError(err, "replay"))
		return
	}

	RespondJSON(w, http.StatusOK, result)
}

// Delete removes a stored request.
func (h *ReplayHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		RespondError(w, http.StatusBadRequest, "INVALID_ID", "invalid request ID")
		return
	}

	if err := h.service.Delete(r.Context(), id); err != nil {
		RespondError(w, http.StatusInternalServerError, "DB_ERROR", safeError(err, "database"))
		return
	}

	RespondJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() || ip.IsUnspecified() {
		return true
	}
	// Block known cloud metadata endpoints
	metadataCIDRs := []string{
		"169.254.169.254/32",  // AWS/GCP/Azure metadata (IPv4)
		"fd00:ec2::254/128",   // AWS metadata (IPv6)
		"100.100.100.200/32",  // Alibaba Cloud metadata
	}
	for _, cidr := range metadataCIDRs {
		_, netBlock, _ := net.ParseCIDR(cidr)
		if netBlock != nil && netBlock.Contains(ip) {
			return true
		}
	}
	return false
}
