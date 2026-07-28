package auth

import (
	"net/http"
	"strings"
)

// Role definitions with hierarchical permissions.
const (
	RoleViewer  = "viewer"  // Read-only access
	RoleAnalyst = "analyst" // Read + view logs/analytics
	RoleEditor  = "editor"  // Read + write rules/settings
	RoleAdmin   = "admin"   // Full access
)

// Permission definitions.
const (
	PermViewDashboard = "view_dashboard"
	PermViewLogs      = "view_logs"
	PermViewAnalytics = "view_analytics"
	PermManageRules   = "manage_rules"
	PermManageSettings = "manage_settings"
	PermManageUsers   = "manage_users"
	PermExportData    = "export_data"
	PermReplayRequests = "replay_requests"
	PermManageHoneypot = "manage_honeypot"
)

// rolePermissions maps roles to their allowed permissions.
var rolePermissions = map[string][]string{
	RoleViewer: {
		PermViewDashboard,
	},
	RoleAnalyst: {
		PermViewDashboard,
		PermViewLogs,
		PermViewAnalytics,
		PermExportData,
	},
	RoleEditor: {
		PermViewDashboard,
		PermViewLogs,
		PermViewAnalytics,
		PermExportData,
		PermManageRules,
		PermManageSettings,
		PermReplayRequests,
		PermManageHoneypot,
	},
	RoleAdmin: {
		PermViewDashboard,
		PermViewLogs,
		PermViewAnalytics,
		PermExportData,
		PermManageRules,
		PermManageSettings,
		PermManageUsers,
		PermReplayRequests,
		PermManageHoneypot,
	},
}

// HasPermission checks if a role has a specific permission.
func HasPermission(role, permission string) bool {
	role = normalizeRole(role)
	perms, ok := rolePermissions[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == permission {
			return true
		}
	}
	return false
}

// normalizeRole trims whitespace and lowercases the role to defend against
// case-only variations (e.g. "Admin" vs "admin"). Unknown casing still maps
// to its canonical role constant.
func normalizeRole(role string) string {
	role = strings.TrimSpace(strings.ToLower(role))
	switch role {
	case "viewer", "read", "readonly", "read-only":
		return RoleViewer
	case "analyst", "ops", "operator":
		return RoleAnalyst
	case "editor", "rule-admin", "ruleadmin":
		return RoleEditor
	case "admin", "administrator", "superadmin", "root":
		return RoleAdmin
	}
	return role
}

// RequirePermission creates middleware that requires a specific permission.
func RequirePermission(permission string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := ClaimsFromContext(r.Context())
		if claims == nil {
			http.Error(w, `{"success":false,"error":{"code":"UNAUTHORIZED","message":"authentication required"}}`, http.StatusUnauthorized)
			return
		}

		if !HasPermission(claims.Role, permission) {
			http.Error(w, `{"success":false,"error":{"code":"FORBIDDEN","message":"insufficient permissions"}}`, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RequireRole creates middleware that requires a minimum role level.
func RequireRole(minRole string, next http.Handler) http.Handler {
	roleLevel := map[string]int{
		RoleViewer:  0,
		RoleAnalyst: 1,
		RoleEditor:  2,
		RoleAdmin:   3,
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := ClaimsFromContext(r.Context())
		if claims == nil {
			http.Error(w, `{"success":false,"error":{"code":"UNAUTHORIZED","message":"authentication required"}}`, http.StatusUnauthorized)
			return
		}

		userLevel, ok := roleLevel[normalizeRole(claims.Role)]
		if !ok {
			http.Error(w, `{"success":false,"error":{"code":"FORBIDDEN","message":"invalid role"}}`, http.StatusForbidden)
			return
		}

		requiredLevel, ok := roleLevel[normalizeRole(minRole)]
		if !ok {
			http.Error(w, `{"success":false,"error":{"code":"FORBIDDEN","message":"invalid required role"}}`, http.StatusForbidden)
			return
		}

		if userLevel < requiredLevel {
			http.Error(w, `{"success":false,"error":{"code":"FORBIDDEN","message":"insufficient role level"}}`, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
