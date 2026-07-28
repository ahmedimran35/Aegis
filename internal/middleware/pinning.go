package middleware

import (
	"sync"
)

// PinTable maps SNI → expected cert SHA-256 fingerprint (hex). When a TLS
// connection is bound for an SNI in the table and the peer certificate
// fingerprint does not match, the request is rejected.
//
// Pinning is opt-in: an empty table disables the check entirely. Operators
// load pins via settings API or via the AEGIS_PINNED_FINGERPRINTS env var.
//
// Storage format: fingerprint is the lower-case hex SHA-256 of the DER
// peer certificate. To compute a pin: `openssl x509 -in cert.pem
// -noout -fingerprint -sha256 | tr -d ':' | tr '[:upper:]' '[:lower:]'`.
type PinTable struct {
	mu    sync.RWMutex
	pins  map[string][]string // sni → accepted fingerprints (any match)
	hits  map[string]int      // sni → violation count (for stats)
}

var globalPins = &PinTable{pins: make(map[string][]string), hits: make(map[string]int)}

// SetPins replaces the global pin table. Pass nil or empty to disable.
func SetPins(pins map[string][]string) {
	globalPins.mu.Lock()
	defer globalPins.mu.Unlock()
	globalPins.pins = make(map[string][]string)
	for k, v := range pins {
		if len(v) > 0 {
			globalPins.pins[k] = append([]string(nil), v...)
		}
	}
}

// AddPin adds a fingerprint to an SNI entry. Appends if SNI exists, else
// creates the entry.
func AddPin(sni, fp string) {
	globalPins.mu.Lock()
	defer globalPins.mu.Unlock()
	if globalPins.pins == nil {
		globalPins.pins = make(map[string][]string)
	}
	globalPins.pins[sni] = append(globalPins.pins[sni], fp)
}

// CheckPin returns (pass, fingerprint). If pinning is disabled (empty
// table) pass is always true. Otherwise pass is true if the provided
// fingerprint matches one of the accepted fingerprints for the SNI.
//
// Records a miss in the hits counter regardless of pass/fail for stats.
func CheckPin(sni, fingerprint string) (pass bool, recordedMiss bool) {
	globalPins.mu.RLock()
	if len(globalPins.pins) == 0 {
		globalPins.mu.RUnlock()
		return true, false
	}
	allowed, ok := globalPins.pins[sni]
	if !ok {
		// No pin registered for this SNI → no constraint → pass.
		globalPins.mu.RUnlock()
		return true, false
	}
	for _, a := range allowed {
		if a == fingerprint {
			globalPins.mu.RUnlock()
			return true, false
		}
	}
	globalPins.mu.RUnlock()
	globalPins.mu.Lock()
	globalPins.hits[sni]++
	globalPins.mu.Unlock()
	return false, true
}

// ViolationCount returns the number of pinning misses for an SNI.
func ViolationCount(sni string) int {
	globalPins.mu.RLock()
	defer globalPins.mu.RUnlock()
	return globalPins.hits[sni]
}

// ResetViolations clears the violation counters.
func ResetViolations() {
	globalPins.mu.Lock()
	globalPins.hits = make(map[string]int)
	globalPins.mu.Unlock()
}
