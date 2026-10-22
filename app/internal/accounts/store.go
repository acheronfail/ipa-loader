// Package accounts persists reusable sessions through an OS credential vault.
// Passwords are never accepted or stored here.
package accounts

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"

	"ipa-loader/app/internal/apple"
)

const maxData = 1 << 20

type Backend interface {
	Read() ([]byte, error)
	Write([]byte) error
}

type Snapshot struct {
	Version  int              `json:"version"`
	Active   string           `json:"active"`
	Sessions []*apple.Session `json:"sessions"`
}

func (Snapshot) String() string   { return "Saved Apple accounts (private)" }
func (Snapshot) GoString() string { return "Saved Apple accounts (private)" }

type Store struct {
	mu      sync.Mutex
	backend Backend
}

func New(backend Backend) *Store { return &Store{backend: backend} }
func Native() *Store             { return New(nativeBackend{}) }

func Key(username string) string { return strings.ToLower(strings.TrimSpace(username)) }

func validSession(s *apple.Session) bool {
	if s == nil {
		return false
	}
	for _, v := range []string{s.Username, s.DSID, s.Token, s.IdentityFP} {
		if strings.TrimSpace(v) == "" || len(v) > 65536 || strings.ContainsAny(v, "\x00\r\n") {
			return false
		}
	}
	return len(s.Username) <= 320
}

func (s *Store) load() (Snapshot, error) {
	data, err := s.backend.Read()
	if err != nil {
		return Snapshot{}, err
	}
	if len(data) == 0 {
		return Snapshot{Version: 1}, nil
	}
	var state Snapshot
	if len(data) > maxData || json.Unmarshal(data, &state) != nil || state.Version != 1 || len(state.Sessions) > 50 {
		return Snapshot{}, errors.New("Saved accounts could not be read from secure storage")
	}
	seen := map[string]bool{}
	for _, session := range state.Sessions {
		if !validSession(session) || seen[Key(session.Username)] {
			return Snapshot{}, errors.New("Saved account data is invalid")
		}
		seen[Key(session.Username)] = true
	}
	if state.Active != "" && !seen[Key(state.Active)] {
		return Snapshot{}, errors.New("Saved account selection is invalid")
	}
	return state, nil
}

func (s *Store) Load() (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

func (s *Store) change(fn func(*Snapshot) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.load()
	if err != nil {
		return err
	}
	if err = fn(&state); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil || len(data) > maxData {
		return errors.New("Too many saved accounts")
	}
	return s.backend.Write(data)
}

func (s *Store) Save(session *apple.Session) error {
	if !validSession(session) {
		return errors.New("This session cannot be saved")
	}
	return s.change(func(state *Snapshot) error {
		copy := *session
		for i, existing := range state.Sessions {
			if Key(existing.Username) == Key(copy.Username) {
				state.Sessions[i] = &copy
				state.Active = copy.Username
				return nil
			}
		}
		if len(state.Sessions) >= 50 {
			return errors.New("Too many saved accounts")
		}
		state.Sessions = append(state.Sessions, &copy)
		state.Active = copy.Username
		return nil
	})
}

// Select changes the next-launch account without rewriting the session token.
func (s *Store) Select(username string) error {
	return s.change(func(state *Snapshot) error {
		for _, existing := range state.Sessions {
			if Key(existing.Username) == Key(username) {
				state.Active = existing.Username
				return nil
			}
		}
		return errors.New("This account is no longer saved; sign in again")
	})
}

func (s *Store) Remove(username string) error {
	return s.change(func(state *Snapshot) error {
		kept := state.Sessions[:0]
		for _, existing := range state.Sessions {
			if Key(existing.Username) != Key(username) {
				kept = append(kept, existing)
			}
		}
		state.Sessions = kept
		if Key(state.Active) == Key(username) {
			state.Active = ""
		}
		return nil
	})
}

// Deactivate signs out persistently while retaining the saved sign-in.
func (s *Store) Deactivate() error {
	return s.change(func(state *Snapshot) error { state.Active = ""; return nil })
}
