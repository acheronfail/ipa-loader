package purego

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"sync"
)

// Store retains one machine identity across accounts and application restarts.
// Initialization is lazy; creating a Store never contacts Apple.
type Store struct {
	mu        sync.Mutex
	path      string
	client    *http.Client
	state     *State
	provision func(context.Context, *http.Client) (*State, error)
}

func NewStore(path string, client *http.Client) *Store {
	return &Store{path: path, client: client, provision: Provision}
}

func (s *Store) Headers(ctx context.Context) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.state != nil {
		return s.state.Headers(ctx)
	}
	if !filepath.IsAbs(s.path) {
		return nil, errors.New("Machine state requires an absolute storage path")
	}
	if err := ensureStateDir(filepath.Dir(s.path)); err != nil {
		return nil, errors.New("Could not open private machine-state directory")
	}
	release, err := lockState(s.path + ".lock")
	if err != nil {
		return nil, errors.New("Machine state is busy or its permissions are unsafe; close other IPA Loader instances and try again")
	}
	defer release()
	raw, err := readState(s.path)
	if err != nil {
		return nil, errors.New("Could not read private machine state")
	}
	defer clear(raw)
	var state *State
	if len(raw) != 0 {
		state = new(State)
		if json.Unmarshal(raw, state) != nil {
			return nil, errors.New("Saved machine state is invalid; it has been preserved")
		}
	} else {
		state, err = s.provision(ctx, s.client)
		if err != nil {
			return nil, err
		}
		raw, err = json.Marshal(state)
		if err != nil {
			return nil, errors.New("Could not encode machine state")
		}
		defer clear(raw)
		if _, err = state.Headers(ctx); err != nil {
			return nil, err
		}
		if err = writeState(s.path, raw); err != nil {
			return nil, errors.New("Could not retain private machine state; login has not started")
		}
	}
	headers, err := state.Headers(ctx)
	if err != nil {
		return nil, err
	}
	s.state = state
	return headers, nil
}
