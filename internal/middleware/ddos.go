package middleware

import (
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// trackedCounter wraps an atomic counter with a last-access timestamp.
type trackedCounter struct {
	counter  atomic.Int32
	lastSeen atomic.Int64 // unix nano
}

func (tc *trackedCounter) Add(delta int32) int32 {
	tc.lastSeen.Store(time.Now().UnixNano())
	return tc.counter.Add(delta)
}

func (tc *trackedCounter) Load() int32 {
	return tc.counter.Load()
}

// DDoSProtector provides connection-level throttling.
type DDoSProtector struct {
	maxConcurrent    int32
	maxPerIP         int32
	maxNewPerSecond  int32
	maxReqsPerConn   int32
	maxTrackedIPs    int
	maxTrackedConns  int

	currentConns     atomic.Int32
	connPerIP        sync.Map // ip -> *trackedCounter
	newConnCounter   atomic.Int32
	reqPerConn       sync.Map // remoteAddr -> *trackedCounter

	stopCh chan struct{}
}

// DDoSConfig holds DDoS protection settings.
type DDoSConfig struct {
	MaxConcurrentConns   int
	MaxConnsPerIP        int
	MaxNewConnsPerSecond int
	MaxReqsPerConn       int
	MaxTrackedIPs        int // max IPs to track in connPerIP (0 = unlimited)
	MaxTrackedConns      int // max connections to track in reqPerConn (0 = unlimited)
}

// NewDDoSProtector creates a DDoS protector.
func NewDDoSProtector(cfg DDoSConfig) *DDoSProtector {
	maxTrackedIPs := cfg.MaxTrackedIPs
	if maxTrackedIPs <= 0 {
		maxTrackedIPs = 10000 // default max 10k tracked IPs
	}
	maxTrackedConns := cfg.MaxTrackedConns
	if maxTrackedConns <= 0 {
		maxTrackedConns = 50000 // default max 50k tracked connections
	}

	d := &DDoSProtector{
		maxConcurrent:    int32(cfg.MaxConcurrentConns),
		maxPerIP:         int32(cfg.MaxConnsPerIP),
		maxNewPerSecond:  int32(cfg.MaxNewConnsPerSecond),
		maxReqsPerConn:   int32(cfg.MaxReqsPerConn),
		maxTrackedIPs:    maxTrackedIPs,
		maxTrackedConns:  maxTrackedConns,
		stopCh:           make(chan struct{}),
	}

	// Reset new connection counter every second
	go func() {
		// M-4: never let a panic in the background goroutine crash the
		// process; recover and continue.
		defer func() {
			if r := recover(); r != nil {
				log.Printf("ddos: counter reset panic recovered: %v", r)
			}
		}()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				d.newConnCounter.Store(0)
			case <-d.stopCh:
				return
			}
		}
	}()

	// Evict stale per-IP and per-connection counters every 5 minutes
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("ddos: counter evict panic recovered: %v", r)
			}
		}()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cutoff := time.Now().Add(-10 * time.Minute).UnixNano()
				d.connPerIP.Range(func(key, value any) bool {
					if tc, ok := value.(*trackedCounter); ok && tc.lastSeen.Load() < cutoff {
						d.connPerIP.Delete(key)
					}
					return true
				})
				d.reqPerConn.Range(func(key, value any) bool {
					if tc, ok := value.(*trackedCounter); ok && tc.lastSeen.Load() < cutoff {
						d.reqPerConn.Delete(key)
					}
					return true
				})
			case <-d.stopCh:
				return
			}
		}
	}()

	return d
}

func (d *DDoSProtector) getIPCounter(ip string) *trackedCounter {
	val, ok := d.connPerIP.Load(ip)
	if !ok {
		counter := &trackedCounter{}
		counter.lastSeen.Store(time.Now().UnixNano())
		val, _ = d.connPerIP.LoadOrStore(ip, counter)

		// Enforce max tracked IPs with LRU eviction. M-8: bound the
		// working slice by maxTrackedIPs+1 so a burst of new IPs
		// cannot trigger a transient allocation that is many times
		// larger than the limit.
		d.enforceMaxTrackedIPs()
	}
	return val.(*trackedCounter)
}

// boundForEviction caps the eviction loop count at
// max(maxTrackedIPs, hardCap) so the per-call allocation in
// enforceMaxTrackedIPs never explodes.
func (d *DDoSProtector) evictionBudget() int {
	budget := d.maxTrackedIPs + 1
	if budget < 1024 {
		budget = 1024
	}
	return budget
}

func (d *DDoSProtector) getReqCounter(addr string) *trackedCounter {
	val, ok := d.reqPerConn.Load(addr)
	if !ok {
		counter := &trackedCounter{}
		counter.lastSeen.Store(time.Now().UnixNano())
		val, _ = d.reqPerConn.LoadOrStore(addr, counter)

		// Enforce max tracked connections with LRU eviction
		d.enforceMaxTrackedConns()
	}
	return val.(*trackedCounter)
}

// enforceMaxTrackedIPs evicts oldest entries if connPerIP exceeds maxTrackedIPs.
//
// M-8: bound the working `entries` slice by maxTrackedIPs+1 so a burst
// of new IPs cannot trigger a transient allocation that is many times
// the configured limit.
func (d *DDoSProtector) enforceMaxTrackedIPs() {
	if d.maxTrackedIPs <= 0 {
		return
	}

	count := 0
	d.connPerIP.Range(func(_, _ any) bool {
		count++
		return true
	})

	if count <= d.maxTrackedIPs {
		return
	}

	toEvict := count - d.maxTrackedIPs
	if toEvict < 1 {
		toEvict = 1
	}

	type entry struct {
		key       string
		lastSeen  int64
	}

	budget := d.evictionBudget()
	if count > budget {
		count = budget
	}

	entries := make([]entry, 0, count)
	d.connPerIP.Range(func(key, value any) bool {
		if len(entries) >= budget {
			return false
		}
		if tc, ok := value.(*trackedCounter); ok {
			entries = append(entries, entry{key: key.(string), lastSeen: tc.lastSeen.Load()})
		}
		return true
	})

	for i := 0; i < toEvict && i < len(entries); i++ {
		minIdx := i
		for j := i + 1; j < len(entries); j++ {
			if entries[j].lastSeen < entries[minIdx].lastSeen {
				minIdx = j
			}
		}
		if minIdx != i {
			entries[i], entries[minIdx] = entries[minIdx], entries[i]
		}
		d.connPerIP.Delete(entries[i].key)
	}
}

// enforceMaxTrackedConns evicts oldest entries if reqPerConn exceeds maxTrackedConns.
func (d *DDoSProtector) enforceMaxTrackedConns() {
	if d.maxTrackedConns <= 0 {
		return
	}

	count := 0
	d.reqPerConn.Range(func(_, _ any) bool {
		count++
		return true
	})

	if count <= d.maxTrackedConns {
		return
	}

	toEvict := count - d.maxTrackedConns
	if toEvict < 1 {
		toEvict = 1
	}

	type entry struct {
		key      string
		lastSeen int64
	}

	budget := d.maxTrackedConns + 1
	if budget < 1024 {
		budget = 1024
	}
	if count > budget {
		count = budget
	}
	entries := make([]entry, 0, count)
	d.reqPerConn.Range(func(key, value any) bool {
		if len(entries) >= budget {
			return false
		}
		if tc, ok := value.(*trackedCounter); ok {
			entries = append(entries, entry{key: key.(string), lastSeen: tc.lastSeen.Load()})
		}
		return true
	})

	for i := 0; i < toEvict && i < len(entries); i++ {
		minIdx := i
		for j := i + 1; j < len(entries); j++ {
			if entries[j].lastSeen < entries[minIdx].lastSeen {
				minIdx = j
			}
		}
		if minIdx != i {
			entries[i], entries[minIdx] = entries[minIdx], entries[i]
		}
		d.reqPerConn.Delete(entries[i].key)
	}
}


// Stop halts background goroutines.
func (d *DDoSProtector) Stop() {
	close(d.stopCh)
}

// Middleware returns the DDoS protection middleware.
func (d *DDoSProtector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		ipStr := ""
		if ip != nil {
			ipStr = ip.String()
		}

		// Check concurrent connections
		conns := d.currentConns.Add(1)
		if conns > d.maxConcurrent {
			d.currentConns.Add(-1)
			log.Printf("ddos: max concurrent connections reached (%d)", conns)
			writeBlockError(w, "DDOS_BLOCKED", "too many concurrent connections")
			return
		}
		defer d.currentConns.Add(-1)

		// Check per-IP connections
		if ipStr != "" {
			ipCounter := d.getIPCounter(ipStr)
			ipConns := ipCounter.Add(1)
			if ipConns > d.maxPerIP {
				ipCounter.Add(-1)
				log.Printf("ddos: max connections per IP reached for %s (%d)", sanitizeLog(ipStr), ipConns)
				writeBlockError(w, "DDOS_BLOCKED", "too many connections from your IP")
				return
			}
			defer ipCounter.Add(-1)
		}

		// Check new connections per second
		newConns := d.newConnCounter.Add(1)
		if newConns > d.maxNewPerSecond {
			log.Printf("ddos: max new connections per second reached (%d)", newConns)
			writeBlockError(w, "DDOS_BLOCKED", "connection rate limit exceeded")
			return
		}

		// Check requests per connection
		reqCounter := d.getReqCounter(r.RemoteAddr)
		reqs := reqCounter.Add(1)
		if reqs > d.maxReqsPerConn {
			log.Printf("ddos: max requests per connection reached for %s (%d)", sanitizeLog(r.RemoteAddr), reqs)
			writeBlockError(w, "DDOS_BLOCKED", "too many requests on this connection")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ConnStateHandler tracks connection lifecycle for HTTP/1.1.
func (d *DDoSProtector) ConnStateHandler() func(net.Conn, http.ConnState) {
	return func(conn net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			d.newConnCounter.Add(1)
		case http.StateClosed, http.StateHijacked:
			d.reqPerConn.Delete(conn.RemoteAddr().String())
		}
	}
}
