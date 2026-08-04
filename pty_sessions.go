package main

import (
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

// livePty holds a running PTY that can be reattached across WebSocket reconnects.
type livePty struct {
	mu         sync.Mutex
	sessionID  string
	cmd        *exec.Cmd
	ptmx       *os.File
	createdAt  time.Time
	lastActive time.Time
	attached   bool
}

type ptyRegistry struct {
	mu       sync.Mutex
	sessions map[string]*livePty
}

func newPtyRegistry() *ptyRegistry {
	return &ptyRegistry{sessions: make(map[string]*livePty)}
}

func (r *ptyRegistry) getOrCreate(sessionID, shell, ps1 string) (*livePty, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if sessionID != "" {
		if existing, ok := r.sessions[sessionID]; ok {
			existing.mu.Lock()
			if existing.attached {
				existing.mu.Unlock()
				return nil, false, errSessionBusy
			}
			existing.attached = true
			existing.lastActive = time.Now()
			existing.mu.Unlock()
			return existing, true, nil
		}
	}

	cmd := exec.Command(shell, "-i")
	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		"PS1="+ps1,
	)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, false, err
	}

	live := &livePty{
		sessionID:  sessionID,
		cmd:        cmd,
		ptmx:       ptmx,
		createdAt:  time.Now(),
		lastActive: time.Now(),
		attached:   true,
	}
	if sessionID != "" {
		r.sessions[sessionID] = live
	}
	return live, false, nil
}

func (r *ptyRegistry) detach(sessionID string) {
	if sessionID == "" {
		return
	}
	r.mu.Lock()
	live, ok := r.sessions[sessionID]
	r.mu.Unlock()
	if !ok {
		return
	}
	live.mu.Lock()
	live.attached = false
	live.lastActive = time.Now()
	live.mu.Unlock()
}

func (r *ptyRegistry) destroy(sessionID string) {
	if sessionID == "" {
		return
	}
	r.mu.Lock()
	live, ok := r.sessions[sessionID]
	if ok {
		delete(r.sessions, sessionID)
	}
	r.mu.Unlock()
	if ok {
		cleanup(live.cmd, live.ptmx)
	}
}

// reapIdle destroys detached sessions whose lastActive exceeds idleFor.
func (r *ptyRegistry) reapIdle(idleFor time.Duration) {
	cutoff := time.Now().Add(-idleFor)
	r.mu.Lock()
	var doomed []string
	for id, live := range r.sessions {
		live.mu.Lock()
		stale := !live.attached && live.lastActive.Before(cutoff)
		live.mu.Unlock()
		if stale {
			doomed = append(doomed, id)
		}
	}
	r.mu.Unlock()
	for _, id := range doomed {
		log.Printf("[terminal] reaping idle detached session %s", id)
		r.destroy(id)
	}
}

var errSessionBusy = &sessionBusyError{}

type sessionBusyError struct{}

func (e *sessionBusyError) Error() string { return "session already attached" }

// pumpPtyToWS copies PTY output to the websocket until error or done.
func pumpPtyToWS(ptmx *os.File, conn *websocket.Conn, done <-chan struct{}) {
	buf := make([]byte, 4096)
	for {
		select {
		case <-done:
			return
		default:
		}
		n, err := ptmx.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("[terminal] pty read error: %v", err)
			}
			return
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
			return
		}
	}
}
