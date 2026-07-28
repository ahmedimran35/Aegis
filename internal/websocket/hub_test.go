package websocket

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestHubBroadcast(t *testing.T) {
	hub := NewHub()
	defer hub.Stop()

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(hub.ServeHTTP))
	defer server.Close()

	// Connect a client with Origin header matching the server host
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	header := http.Header{"Origin": {server.URL}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Wait for registration
	time.Sleep(50 * time.Millisecond)

	if hub.ClientCount() != 1 {
		t.Errorf("client count = %d, want 1", hub.ClientCount())
	}

	// Broadcast event
	hub.Broadcast("test", map[string]string{"key": "value"})

	// Read message
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var event Event
	if err := json.Unmarshal(msg, &event); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if event.Event != "test" {
		t.Errorf("event = %q, want test", event.Event)
	}
}

func TestHubMultipleClients(t *testing.T) {
	hub := NewHub()
	defer hub.Stop()

	server := httptest.NewServer(http.HandlerFunc(hub.ServeHTTP))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	header := http.Header{"Origin": {server.URL}}

	// Connect 3 clients
	conns := make([]*websocket.Conn, 3)
	for i := range conns {
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer conn.Close()
		conns[i] = conn
	}

	time.Sleep(50 * time.Millisecond)

	if hub.ClientCount() != 3 {
		t.Errorf("client count = %d, want 3", hub.ClientCount())
	}

	// Broadcast
	hub.Broadcast("multi", "hello")

	// All clients should receive
	for i, conn := range conns {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, msg, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("client %d read: %v", i, err)
		}
		var event Event
		json.Unmarshal(msg, &event)
		if event.Event != "multi" {
			t.Errorf("client %d event = %q, want multi", i, event.Event)
		}
	}
}

func TestHubClientDisconnect(t *testing.T) {
	hub := NewHub()
	defer hub.Stop()

	server := httptest.NewServer(http.HandlerFunc(hub.ServeHTTP))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	header := http.Header{"Origin": {server.URL}}
	conn, _, _ := websocket.DefaultDialer.Dial(wsURL, header)
	time.Sleep(50 * time.Millisecond)

	if hub.ClientCount() != 1 {
		t.Errorf("client count = %d, want 1", hub.ClientCount())
	}

	conn.Close()
	time.Sleep(100 * time.Millisecond)

	if hub.ClientCount() != 0 {
		t.Errorf("client count after disconnect = %d, want 0", hub.ClientCount())
	}
}
