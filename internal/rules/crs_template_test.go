package rules

import "testing"

func TestCRSPackAvailableAsTemplate(t *testing.T) {
	tmpl := GetTemplate("crs-pl2")
	if tmpl == nil {
		t.Fatalf("crs-pl2 template missing")
	}
	if len(tmpl.Rules) != len(CuratedCRSPack) {
		t.Errorf("template has %d rules, pack has %d", len(tmpl.Rules), len(CuratedCRSPack))
	}
	if tmpl.ParanoiaLevel != 2 {
		t.Errorf("paranoia = %d, want 2", tmpl.ParanoiaLevel)
	}
}
