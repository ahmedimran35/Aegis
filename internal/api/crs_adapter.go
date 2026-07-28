package api

import (
	"time"

	"github.com/user/waf/internal/rules"
)

// CRSStatsAdapter wraps *rules.CRSUpdater so the api package can use
// it without importing the rules package directly (avoids a cycle
// since rules also imports the api types via middleware).
type CRSStatsAdapter struct {
	Updater *rules.CRSUpdater
}

// Stats implements CRSStatsGetter by projecting rules.CRSStats into the
// api package's CRSStats.
func (a *CRSStatsAdapter) Stats() CRSStats {
	if a == nil || a.Updater == nil {
		return CRSStats{}
	}
	s := a.Updater.Stats()
	return CRSStats{
		LastFetch:  s.LastFetch,
		LastError:  s.LastError,
		Imported:   s.Imported,
		Skipped:    s.Skipped,
		Ref:        s.Ref,
		IntervalNS: int64(s.Interval),
	}
}

// NewCRSStatsAdapter is a small constructor for callers that prefer
// the functional form over struct literal.
func NewCRSStatsAdapter(u *rules.CRSUpdater) *CRSStatsAdapter {
	return &CRSStatsAdapter{Updater: u}
}

// Touch the import to keep `time` available in this file for future use.
var _ = time.Time{}