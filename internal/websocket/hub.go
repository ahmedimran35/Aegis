package websocket

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	wafmw "github.com/user/waf/internal/middleware"
)

// extractWSClientIP extracts the client IP from the WebSocket upgrade request.
func extractWSClientIP(r *http.Request) net.IP {
	ip := wafmw.ExtractClientIP(r)
	if ip == nil {
		return net.ParseIP("127.0.0.1")
	}
	return ip
}

// ValidateTokenFunc validates a JWT token string. Returns nil if valid.
type ValidateTokenFunc func(token string) error

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			// Non-browser client: validate token from Sec-WebSocket-Protocol header
			// (avoids logging JWT in URL query parameters)
			token := r.Header.Get("Sec-WebSocket-Protocol")
			if token == "" || tokenValidator == nil {
				return false
			}
			if err := tokenValidator(token); err != nil {
				log.Printf("ws: token validation failed: %v", err)
				return false
			}
			return true
		}
		// P-FIX (CRIT-3): reject the literal "null" origin used by
		// sandboxed iframes / file:// — a known CSWSH vector.
		if origin == "null" {
			return false
		}
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		// P-FIX: also reject origins whose hostname is empty (browser
		// bug, blocked frame, etc).
		originHost := u.Hostname()
		if originHost == "" {
			return false
		}
		originPort := u.Port()
		if originPort == "" {
			if u.Scheme == "https" {
				originPort = "443"
			} else {
				originPort = "80"
			}
		}
		reqHost, reqPort, err := net.SplitHostPort(r.Host)
		if err != nil {
			reqHost = r.Host
			if r.TLS != nil {
				reqPort = "443"
			} else {
				reqPort = "80"
			}
		}
		reqScheme := "http"
		if r.TLS != nil {
			reqScheme = "https"
		}
		// P-FIX: only honor X-Forwarded-Proto when the request came from
		// a configured trusted proxy; otherwise an attacker can spoof the
		// scheme to make the WS check accept an "https://" origin against
		// a plaintext listener.
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" && wafmw.IsTrustedProxyReq(r) {
			reqScheme = proto
		}
		return originHost == reqHost && originPort == reqPort && u.Scheme == reqScheme
	},
}

// tokenValidator is set by main to validate WebSocket auth tokens.
var tokenValidator ValidateTokenFunc

// SetTokenValidator sets the function used to validate WebSocket auth tokens.
func SetTokenValidator(v ValidateTokenFunc) {
	tokenValidator = v
}

const maxClients = 100

// Event is a WebSocket message pushed to clients.
type Event struct {
	Event     string      `json:"event"`
	Data      interface{} `json:"data"`
	Timestamp string      `json:"timestamp"`
}

// Client is a connected WebSocket client.
type Client struct {
	conn *websocket.Conn
	send chan []byte
	// id is the connection identifier used by wsGuard for per-connection
	// rate-limiting. Empty for legacy clients (pre-WSGuard upgrade).
	id string
}

// Hub manages connected WebSocket clients and broadcasts events.
type Hub struct {
	mu         sync.RWMutex
	clients    map[*Client]bool
	register   chan *Client
	unregister chan *Client
	stopCh     chan struct{}
	stopOnce   sync.Once
	inspector  *WSInspector
	// P-FREE-3: optional wsGuard used to enforce per-frame size and
	// per-connection message-rate limits. nil = fall back to hardcoded
	// defaults (16 KiB read ceiling, 60 s read deadline).
	wsGuard WSGuarder
	// M-11: counter for Broadcast drops so /metrics can expose them.
	broadcastDrops atomic.Int64
}

// WSGuarder is the subset of *middleware.WSGuard that the hub depends
// on. Kept as an interface so internal/websocket stays import-clean of
// internal/middleware (which would be a cycle).
type WSGuarder interface {
	FrameLimit() int64
	CheckMessageRate(ctx context.Context, connID string) bool
}

// NewHub creates and starts a WebSocket hub.
func NewHub() *Hub {
	h := &Hub{
		clients:    make(map[*Client]bool),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		stopCh:     make(chan struct{}),
	}
	go h.run()
	return h
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			log.Printf("ws: client connected (%d total)", len(h.clients))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			log.Printf("ws: client disconnected (%d total)", len(h.clients))

		case <-h.stopCh:
			h.mu.Lock()
			for client := range h.clients {
				close(client.send)
				delete(h.clients, client)
			}
			h.mu.Unlock()
			return
		}
	}
}

// Broadcast sends an event to all connected clients.
func (h *Hub) Broadcast(event string, data interface{}) {
	msg, err := json.Marshal(Event{
		Event:     event,
		Data:      data,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		log.Printf("ws: marshal event: %v", err)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	// M-11: track drops so operators can spot a flood of slow clients.
	for client := range h.clients {
		select {
		case client.send <- msg:
		default:
			h.broadcastDrops.Add(1)
		}
	}
}

// ClientCount returns the number of connected clients.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// SetInspector sets the WebSocket inspector for message filtering.
func (h *Hub) SetInspector(inspector *WSInspector) {
	h.inspector = inspector
}

// SetWSGuard wires the optional WebSocket guard for per-frame size +
// per-connection message-rate limits. Safe to call with nil.
func (h *Hub) SetWSGuard(g WSGuarder) {
	h.wsGuard = g
}

// BroadcastDrops returns the cumulative count of broadcast events that
// were dropped because a client's send buffer was full (M-11).
func (h *Hub) BroadcastDrops() int64 {
	return h.broadcastDrops.Load()
}

// Stop shuts down the hub and disconnects all clients.
func (h *Hub) Stop() {
	h.stopOnce.Do(func() { close(h.stopCh) })
}

// ServeHTTP handles WebSocket upgrade requests.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Limit concurrent WebSocket clients to prevent memory exhaustion
	h.mu.RLock()
	clientCount := len(h.clients)
	h.mu.RUnlock()
	if clientCount >= maxClients {
		http.Error(w, "too many connections", http.StatusTooManyRequests)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws: upgrade: %v", err)
		return
	}

	client := &Client{
		conn: conn,
		send: make(chan []byte, 256),
	}
	// P-FREE-3: per-connection identifier used by wsGuard for the
	// message-rate counter. We use the remote address as a stable,
	// non-PII tag (already recorded in access logs).
	client.id = r.RemoteAddr

	h.register <- client

	// Writer goroutine with write deadline to prevent slow-client goroutine leak
	go func() {
		defer conn.Close()
		// H-12: a panic in the writer goroutine must not crash the process.
		defer func() {
			if r := recover(); r != nil {
				log.Printf("ws: writer panic recovered: %v", r)
			}
		}()
		for msg := range client.send {
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				break
			}
		}
	}()

		// Reader goroutine - inspect messages through Aegis rules
		go func() {
			defer func() {
				if r := recover(); r != nil {
					// H-12: a panic in the reader goroutine must not crash
					// the process. The deferred Close() still runs.
					log.Printf("ws: reader panic recovered: %v", r)
				}
				h.unregister <- client
				conn.Close()
			}()
			// M-10: 16kB read ceiling and a per-message rate limit to keep
			// a misbehaving client from exhausting server resources.
			// P-FREE-3: wsGuard overrides the limits when configured.
			if h.wsGuard != nil {
				conn.SetReadLimit(h.wsGuard.FrameLimit())
			} else {
				conn.SetReadLimit(16384)
			}
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			conn.SetPongHandler(func(string) error {
				conn.SetReadDeadline(time.Now().Add(60 * time.Second))
				return nil
			})
			for {
				_, msg, err := conn.ReadMessage()
				if err != nil {
					break
				}

				// P-FREE-3: per-connection message-rate cap.
				if h.wsGuard != nil && client.id != "" {
					if !h.wsGuard.CheckMessageRate(r.Context(), client.id) {
						conn.WriteMessage(websocket.CloseMessage,
							websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "message rate exceeded"))
						break
					}
				}

				// Inspect message through Aegis rules if inspector is configured
				if h.inspector != nil {
					clientIP := extractWSClientIP(r)
					if !h.inspector.InspectMessage(clientIP, msg) {
						// Message blocked - send close frame and exit
						conn.WriteMessage(websocket.CloseMessage,
							websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "message blocked by Aegis"))
						break
					}
				}
			}
		}()
}
