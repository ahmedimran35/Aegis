package middleware

import (
	"testing"
)

func TestResolveSchema(t *testing.T) {
	SetBOLASchema(map[string]SchemaEntry{
		"/api/users":  {ResourceName: "users", Scope: ScopeUserScoped, PathPrefix: "/api/users"},
		"/api/orders": {ResourceName: "orders", Scope: ScopeTenantScoped, PathPrefix: "/api/orders"},
	})
	defer SetBOLASchema(nil)

	if e := ResolveSchema("/api/users/123"); e == nil || e.ResourceName != "users" {
		t.Fatalf("expected users, got %+v", e)
	}
	if e := ResolveSchema("/api/orders/42"); e == nil || e.Scope != ScopeTenantScoped {
		t.Fatalf("expected tenant-scoped orders, got %+v", e)
	}
	if e := ResolveSchema("/api/posts/1"); e != nil {
		t.Fatalf("expected nil for /api/posts, got %+v", e)
	}
}

func TestAddSchemaEntry(t *testing.T) {
	SetBOLASchema(nil)
	AddSchemaEntry(SchemaEntry{ResourceName: "x", PathPrefix: "/api/x", Scope: ScopePublic})
	if e := ResolveSchema("/api/x/y"); e == nil || e.ResourceName != "x" {
		t.Fatalf("expected x, got %+v", e)
	}
}

func TestCardinalityTrackerBackendMissing(t *testing.T) {
	c := NewCardinalityTracker(nil, 3)
	cnt, spike, err := c.Track("u1:orders:tenant1", "r-001")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if cnt != 0 || spike {
		t.Fatalf("expected 0/false, got %d/%v", cnt, spike)
	}
}
