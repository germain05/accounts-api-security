// Placeholder. The brief says to assume the service exists and is broadly
// competent, so this is not an implementation — it is the minimum needed for the
// Dockerfile and the SCA gate to have something real to chew on, plus the one
// thing from docs/06-log-redaction.md that is a *design* decision rather than an
// implementation detail: sensitive values are their own types whose String() and
// MarshalJSON() are already redacted, so passing one to any formatter anywhere —
// including a third-party library's error path — produces the safe form.
package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
)

// IBAN never prints itself. This is the highest-leverage line in the redaction
// design: it makes the safe behaviour the default rather than a rule to remember.
type IBAN string

func (IBAN) String() string               { return "[REDACTED:iban]" }
func (IBAN) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED:iban]"`), nil }

type CardLast4 string

func (CardLast4) String() string               { return "[REDACTED:last4]" }
func (CardLast4) MarshalJSON() ([]byte, error) { return []byte(`"[REDACTED:last4]"`), nil }

type Account struct {
	ID        string    `json:"account_id"` // pseudonymous join key: logged on purpose
	Name      string    `json:"-"`
	Email     string    `json:"-"`
	IBAN      IBAN      `json:"iban"`
	Last4     CardLast4 `json:"last4"`
	BalanceMi int64     `json:"-"`
}

// MarshalLog is an allowlist. A field added to Account next quarter is invisible
// to logs until somebody adds it here — the default is redaction.
func (a Account) MarshalLog() any {
	return map[string]any{"account_id": a.ID}
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if _, err := os.Stat(os.Getenv("DB_CREDENTIAL_FILE")); err != nil {
		logger.Warn("credential file not mounted", "err", err.Error())
	}
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	http.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	})
	logger.Info("listening", "addr", ":8080")
	_ = http.ListenAndServe(":8080", nil)
}
