package websocket

import (
	"log"
	"net"

	"github.com/user/waf/internal/rules"
)

// WSInspector inspects WebSocket messages through Aegis rules.
type WSInspector struct {
	engine *rules.Engine
	hub    *Hub
}

// NewWSInspector creates a WebSocket inspector.
func NewWSInspector(engine *rules.Engine, hub *Hub) *WSInspector {
	return &WSInspector{
		engine: engine,
		hub:    hub,
	}
}

// InspectMessage checks a WebSocket message against Aegis rules.
// Returns true if the message should be allowed.
func (wi *WSInspector) InspectMessage(clientIP net.IP, message []byte) bool {
	if wi.engine == nil {
		return true
	}

	msg := string(message)
	result := wi.engine.Evaluate(clientIP, "WS", "/", "", "", msg, "", 4)
	if result.Matched {
		log.Printf("ws: blocked message from %s (rule: %s, action: %s)",
			clientIP, result.Rule.Name, result.Action)
		return result.Action != rules.ActionBlock
	}
	return true
}
