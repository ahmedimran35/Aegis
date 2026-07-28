package middleware

import (
	"log"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

// WSInspector inspects WebSocket messages through Aegis rules.
type WSInspector struct {
	mu              sync.RWMutex
	blockedPatterns []string
}

// NewWSInspector creates a WebSocket inspector.
func NewWSInspector() *WSInspector {
	return &WSInspector{}
}

// SetPatterns updates the blocked patterns for WS messages.
func (w *WSInspector) SetPatterns(patterns []string) {
	w.mu.Lock()
	w.blockedPatterns = patterns
	w.mu.Unlock()
}

// InspectMessage checks a WS message against blocked patterns.
func (w *WSInspector) InspectMessage(msg []byte) bool {
	w.mu.RLock()
	patterns := w.blockedPatterns
	w.mu.RUnlock()
	msgStr := string(msg)
	for _, p := range patterns {
		if strings.Contains(strings.ToLower(msgStr), strings.ToLower(p)) {
			return true
		}
	}
	return false
}

// WrapConn wraps a WebSocket connection with message inspection.
func (w *WSInspector) WrapConn(conn *websocket.Conn, clientIP string) *InspectedConn {
	return &InspectedConn{
		Conn:     conn,
		inspector: w,
		clientIP:  clientIP,
	}
}

// InspectedConn wraps websocket.Conn with Aegis inspection.
type InspectedConn struct {
	*websocket.Conn
	inspector *WSInspector
	clientIP  string
}

// ReadMessage inspects incoming WS messages.
func (ic *InspectedConn) ReadMessage() (int, []byte, error) {
	msgType, msg, err := ic.Conn.ReadMessage()
	if err != nil {
		return msgType, msg, err
	}

	if ic.inspector.InspectMessage(msg) {
		log.Printf("ws-inspect: blocked message from %s: %s", ic.clientIP, sanitizeLog(truncate(string(msg), 100)))
		// Send close frame
		ic.Conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "message blocked by Aegis"))
		return msgType, msg, &WSError{Message: "message blocked by Aegis"}
	}

	return msgType, msg, nil
}

// WSError represents an Aegis WebSocket error.
type WSError struct {
	Message string
}

func (e *WSError) Error() string {
	return e.Message
}
