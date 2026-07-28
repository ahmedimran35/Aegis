// Package gdpr provides GDPR data-subject rights: export, delete, and
// retention-based pruning of personal data.
package gdpr

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct {
	pool *pgxpool.Pool
}

// NewService creates a GDPR service.
func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

// Export returns all data we hold for a given user ID.
func (s *Service) Export(ctx context.Context, userID int) (map[string]interface{}, error) {
	if s.pool == nil {
		return nil, fmt.Errorf("no db")
	}
	out := map[string]interface{}{}

	var profile map[string]interface{}
	err := s.pool.QueryRow(ctx,
		`SELECT row_to_json(u) FROM users u WHERE id = $1`, userID,
	).Scan(&profile)
	if err == nil {
		out["profile"] = profile
	}

	sessions, _ := s.pool.Query(ctx,
		`SELECT row_to_json(s) FROM sessions s WHERE user_id = $1`, userID,
	)
	defer sessions.Close()
	var sessList []interface{}
	for sessions.Next() {
		var j map[string]interface{}
		if err := sessions.Scan(&j); err == nil {
			sessList = append(sessList, j)
		}
	}
	out["sessions"] = sessList

	auditRows, _ := s.pool.Query(ctx,
		`SELECT row_to_json(a) FROM audit_log a WHERE reviewed_by = $1 OR username = (SELECT username FROM users WHERE id = $1)`,
		userID,
	)
	defer auditRows.Close()
	var auditList []interface{}
	for auditRows.Next() {
		var j map[string]interface{}
		if err := auditRows.Scan(&j); err == nil {
			auditList = append(auditList, j)
		}
	}
	out["audit_log"] = auditList

	return out, nil
}

// Delete removes all data we hold for a given user ID. Returns counts.
func (s *Service) Delete(ctx context.Context, userID int) (map[string]int, error) {
	if s.pool == nil {
		return nil, fmt.Errorf("no db")
	}
	counts := map[string]int{}

	ct, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	if err != nil {
		return counts, fmt.Errorf("sessions: %w", err)
	}
	counts["sessions"] = int(ct.RowsAffected())

	ct, err = s.pool.Exec(ctx, `DELETE FROM false_positives WHERE reviewed_by = $1`, userID)
	if err != nil {
		return counts, fmt.Errorf("fp: %w", err)
	}
	counts["false_positives"] = int(ct.RowsAffected())

	ct, err = s.pool.Exec(ctx, `DELETE FROM false_negatives WHERE reviewed_by = $1`, userID)
	if err != nil {
		return counts, fmt.Errorf("fn: %w", err)
	}
	counts["false_negatives"] = int(ct.RowsAffected())

	return counts, nil
}

// RetentionWorker periodically deletes request_logs and audit_log entries
// older than retentionDays. Runs in a goroutine; cancel via stopCh.
func (s *Service) RetentionWorker(retentionDays int, interval time.Duration, stopCh <-chan struct{}) {
	if retentionDays <= 0 {
		log.Printf("gdpr: retention disabled (retentionDays=%d)", retentionDays)
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			rl, err := s.pool.Exec(ctx,
				`DELETE FROM request_logs WHERE created_at < NOW() - ($1 || ' days')::interval`,
				fmt.Sprintf("%d", retentionDays))
			if err != nil {
				log.Printf("gdpr: request_logs prune: %v", err)
			} else {
				log.Printf("gdpr: pruned %d request_logs (retention=%dd)", rl.RowsAffected(), retentionDays)
			}
			al, err := s.pool.Exec(ctx,
				`DELETE FROM audit_log WHERE created_at < NOW() - ($1 || ' days')::interval`,
				fmt.Sprintf("%d", retentionDays))
			if err != nil {
				log.Printf("gdpr: audit_log prune: %v", err)
			} else {
				log.Printf("gdpr: pruned %d audit_log (retention=%dd)", al.RowsAffected(), retentionDays)
			}
			cancel()
		}
	}
}

// HandleExport HTTP handler for GET /gdpr/export (current user).
func (s *Service) HandleExport(w http.ResponseWriter, r *http.Request, userID int) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	data, err := s.Export(ctx, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=gdpr-export.json")
	_ = json.NewEncoder(w).Encode(data)
}

// HandleDelete HTTP handler for POST /gdpr/delete (current user).
func (s *Service) HandleDelete(w http.ResponseWriter, r *http.Request, userID int) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	counts, err := s.Delete(ctx, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(counts)
}
