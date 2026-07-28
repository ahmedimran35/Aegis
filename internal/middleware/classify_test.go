package middleware

import (
	"testing"

	"github.com/user/waf/internal/ai"
)

func TestRequestHash(t *testing.T) {
	features := ai.RequestFeatures{
		Method: "GET",
		Path:   "/api/test",
		QueryParams: "foo=bar",
		UserAgent:   "curl/7.0",
	}
	hash1 := requestHash(features)
	hash2 := requestHash(features)
	if hash1 != hash2 {
		t.Errorf("same input produced different hashes: %s vs %s", hash1, hash2)
	}

	// Different input should produce different hash
	features2 := features
	features2.Path = "/api/other"
	hash3 := requestHash(features2)
	if hash1 == hash3 {
		t.Error("different inputs produced same hash")
	}
}
