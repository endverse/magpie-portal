package oidcportal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/yetone/magpie/internal/settings"
)

// Event is something worth telling an admin about outside the portal: an
// application, or a decision. The admin page always shows it; a notifier
// carries it to Feishu or another system.
type Event struct {
	Kind  string    `json:"kind"` // application, approved, rejected, disabled
	Sub   string    `json:"sub"`
	Email string    `json:"email,omitempty"`
	Name  string    `json:"name,omitempty"`
	Text  string    `json:"text"`
	At    time.Time `json:"at"`
}

// Notifier announces an event. A failure to announce is logged and never
// fails the action that caused it.
type Notifier interface {
	Notify(ctx context.Context, e Event) error
}

// NewNotifier builds the notifier a config asks for, nil when it asks for
// none: a generic webhook that receives the event as JSON, a Feishu bot
// webhook that receives a text message, or both.
func NewNotifier(c NotifyConfig) Notifier {
	var all []Notifier
	if c.Webhook != "" {
		all = append(all, &webhookNotifier{url: c.Webhook, client: notifyClient()})
	}
	if c.Feishu != "" {
		all = append(all, &webhookNotifier{url: c.Feishu, feishu: true, client: notifyClient()})
	}
	switch len(all) {
	case 0:
		return nil
	case 1:
		return all[0]
	}
	return multiNotifier(all)
}

type multiNotifier []Notifier

func (m multiNotifier) Notify(ctx context.Context, e Event) error {
	var first error
	for _, n := range m {
		if err := n.Notify(ctx, e); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func notifyClient() *http.Client { return &http.Client{Timeout: 5 * time.Second} }

// webhookNotifier posts the event to a webhook. A Feishu bot takes a text
// message in its own envelope; anything else takes the event itself.
type webhookNotifier struct {
	url    string
	feishu bool
	client *http.Client
}

func (w *webhookNotifier) Notify(ctx context.Context, e Event) error {
	var body []byte
	var err error
	if w.feishu {
		body, err = json.Marshal(map[string]any{
			"msg_type": "text",
			"content":  map[string]string{"text": e.Text},
		})
	} else {
		body, err = json.Marshal(e)
	}
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("notify %s: %s", w.url, resp.Status)
	}
	return nil
}

// Audit is the portal's own log of what admins did: who changed whose
// access, when, and what content was read. Appended, one JSON object a
// line, written 0600.
type Audit struct {
	path string
	mu   sync.Mutex
}

// OpenAudit is the audit log at path; none is written until the first
// entry. An empty path is a log that keeps nothing.
func OpenAudit(path string) *Audit { return &Audit{path: path} }

// AuditPath is the portal's audit log beside its policy file.
func AuditPath() string { return settings.Dir() + "/oidc-audit.jsonl" }

type auditEntry struct {
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Sub    string    `json:"sub,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// Log appends one entry. A failure is logged and otherwise ignored: an
// audit log that cannot be written must not stop an admin's action.
func (a *Audit) Log(actor, action, sub, detail string) {
	if a == nil || a.path == "" {
		return
	}
	e := auditEntry{At: time.Now().UTC(), Actor: actor, Action: action, Sub: sub, Detail: detail}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Printf("oidc portal: audit: %v", err)
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}
