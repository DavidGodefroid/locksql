// Package audit writes the console's append-only JSONL audit trail. One
// record per event; never secrets and never row data.
package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// Events, spec §15.
const (
	EventLogin    = "login"
	EventPolicy   = "policy"   // policy change, applied or refused (see Decision)
	EventRefused  = "refused"  // plan refused by the classifier, the tier or the weight check
	EventApproved = "approved" // the human approved
	EventDenied   = "denied"   // the human denied
	EventTimeout  = "timeout"  // approval timed out
	EventAuto     = "auto"     // auto-approved under --skip-permissions
	EventCatalog  = "catalog"  // catalog read
	EventLogout   = "logout"
)

// Record is one audit event. It has no field able to hold a password or row
// data: Error must already be sanitised by the caller.
type Record struct {
	Event      string `json:"event"`
	Profile    string `json:"profile,omitempty"`
	Engine     string `json:"engine,omitempty"`
	Host       string `json:"host,omitempty"`
	DB         string `json:"db,omitempty"`
	DBUser     string `json:"db_user,omitempty"`
	Class      string `json:"class,omitempty"`
	SQL        string `json:"sql,omitempty"`
	Verdict    string `json:"verdict,omitempty"`
	Decision   string `json:"decision,omitempty"`
	Error      string `json:"error,omitempty"`
	Rows       int64  `json:"rows,omitempty"`
	Affected   int64  `json:"affected,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
	Unmasked   bool   `json:"unmasked,omitempty"`
}

// line is the on-disk shape: the timestamp first, then the record.
type line struct {
	TS string `json:"ts"`
	Record
}

// Log appends records to <stateDir>/locksql/audit.log. The file is opened in
// append mode for each record, so it is never truncated and never held open.
type Log struct {
	path string
	mu   sync.Mutex
}

// Open prepares the audit log under stateDir: the directory is 0700 and the
// file 0600 (Unix), created if missing; existing content is kept.
func Open(stateDir string) (*Log, error) {
	if stateDir == "" {
		return nil, errors.New("audit: empty state dir")
	}
	dir := filepath.Join(stateDir, "locksql")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	l := &Log{path: filepath.Join(dir, "audit.log")}
	f, err := l.open()
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("audit: %w", err)
		}
	}
	return l, nil
}

func (l *Log) open() (*os.File, error) {
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	if runtime.GOOS != "windows" {
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("audit: %w", err)
		}
		if !fi.Mode().IsRegular() {
			f.Close()
			return nil, fmt.Errorf("audit: %s is not a regular file", l.path)
		}
		if fi.Mode().Perm() != 0o600 {
			if err := f.Chmod(0o600); err != nil {
				f.Close()
				return nil, fmt.Errorf("audit: %w", err)
			}
		}
	}
	return f, nil
}

// Path is the audit log file.
func (l *Log) Path() string { return l.path }

// Write appends rec as one JSON line with the current time in RFC 3339.
func (l *Log) Write(rec Record) error {
	if rec.Event == "" {
		return errors.New("audit: record without an event")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	ts := time.Now().Format("2006-01-02T15:04:05.000Z07:00")
	if err := enc.Encode(line{TS: ts, Record: rec}); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := l.open()
	if err != nil {
		return err
	}
	// One write call per record: with O_APPEND the line lands whole.
	if _, err := f.Write(buf.Bytes()); err != nil {
		f.Close()
		return fmt.Errorf("audit: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	return nil
}
