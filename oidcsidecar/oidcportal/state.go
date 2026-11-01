package oidcportal

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yetone/magpie/internal/edit"
)

// User is what the portal keeps of one signed-in person: the key it made
// them, which generation of it, and the scope it last had. Key is the key's
// value, as caller-keys.json holds it; this file is written 0600 beside it.
type User struct {
	Sub        string   `json:"sub"`
	Email      string   `json:"email,omitempty"`
	Name       string   `json:"name,omitempty"`
	Username   string   `json:"username,omitempty"` // Keycloak's preferred_username
	Groups     []string `json:"groups,omitempty"`
	Providers  []string `json:"providers,omitempty"`
	Generation int      `json:"generation"`
	KeyID      string   `json:"keyId,omitempty"`
	// KeyIDs is every key id this person has had, oldest first. Rotation
	// keeps the id; a key removed and made again gets a new one, and the
	// usage page still counts both as this person's.
	KeyIDs    []string  `json:"keyIds,omitempty"`
	Key       string    `json:"key,omitempty"`
	Disabled  bool      `json:"disabled,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// State is the portal's own store, a JSON file: who it has made keys for,
// and which generation of each. A file that can't be read is an error, never
// an empty store: an empty one would make every user a new key.
type State struct {
	path  string
	mu    sync.Mutex
	users map[string]User
}

type stateFile struct {
	Users map[string]User `json:"users"`
}

// OpenState reads path, or starts an empty store when it doesn't exist.
func OpenState(path string) (*State, error) {
	s := &State{path: path, users: map[string]User{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f stateFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if f.Users != nil {
		s.users = f.Users
	}
	return s, nil
}

// Get is a copy of the user's record.
func (s *State) Get(sub string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[sub]
	return u, ok
}

// Update changes one user under the store's lock and writes the store
// before it returns. fn sees the user as it is, and what it leaves is
// kept; an error leaves the store as it was.
func (s *State) Update(sub string, fn func(*User) error) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[sub]
	if u.Sub == "" {
		u.Sub = sub
	}
	before := u
	if err := fn(&u); err != nil {
		return before, err
	}
	u.Sub = sub
	u.UpdatedAt = time.Now().UTC()
	s.users[sub] = u
	if err := s.saveLocked(); err != nil {
		if before.Sub == "" {
			delete(s.users, sub)
		} else {
			s.users[sub] = before
		}
		return before, err
	}
	return u, nil
}

// All is every user the portal has made a key for, by subject.
func (s *State) All() []User {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sub < out[j].Sub })
	return out
}

// rememberKey adds a key id to the person's history, once.
func (u *User) rememberKey(id string) {
	if id == "" {
		return
	}
	for _, k := range u.KeyIDs {
		if k == id {
			return
		}
	}
	u.KeyIDs = append(u.KeyIDs, id)
}

// keyIDs is every id this person's calls may be under: the history, and the
// current id for a record written before the history existed.
func (u User) keyIDs() []string {
	out := append([]string(nil), u.KeyIDs...)
	if u.KeyID != "" {
		found := false
		for _, k := range out {
			if k == u.KeyID {
				found = true
				break
			}
		}
		if !found {
			out = append(out, u.KeyID)
		}
	}
	return out
}

// GetAny is a copy of the record with this subject or email, whichever
// case, for a console admin the config names by email but who has never
// signed in to the portal.
func (s *State) GetAny(who string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[who]; ok {
		return u, true
	}
	for _, u := range s.users {
		if strings.EqualFold(u.Email, who) {
			return u, true
		}
	}
	return User{}, false
}

// keyOwnerLocked is the other person whose record holds keyID, if any. The
// caller holds the state lock: sync runs inside Update, and this answers
// whether a key with a name is already accounted for before it is adopted.
func (s *State) keyOwnerLocked(keyID, except string) (User, bool) {
	if keyID == "" {
		return User{}, false
	}
	for sub, u := range s.users {
		if sub == except {
			continue
		}
		for _, id := range u.keyIDs() {
			if id == keyID {
				return u, true
			}
		}
	}
	return User{}, false
}

func (s *State) saveLocked() error {
	b, err := json.MarshalIndent(stateFile{Users: s.users}, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := edit.WriteAtomic(s.path, b); err != nil {
		return err
	}
	return os.Chmod(s.path, 0o600)
}
