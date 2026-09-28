// Package keyrelease is a mock key-management service implementing the
// key-release pattern: a workload's data-encryption key is only unwrapped
// and returned when the composite attestation verdict for the requesting
// session passes.
//
// The "wrapping" here is AES-GCM under a master key supplied at startup
// (env KMS_MASTER_KEY, 32 hex bytes); the data keys at rest live in a JSON
// file as wrapped blobs. Releases are HMAC-bound to the session nonce so a
// released key cannot be replayed into a different session, and every
// decision — grant or deny — is appended to an audit log.
package keyrelease

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/PeaceXXX/composite-attestation-combiner/internal/evidence"
	"github.com/PeaceXXX/composite-attestation-combiner/internal/policy"
)

// Decision is one audit-log entry.
type Decision struct {
	Time       time.Time `json:"time"`
	WorkloadID string    `json:"workload_id"`
	Granted    bool      `json:"granted"`
	Reasons    []string  `json:"reasons,omitempty"`
}

// KMS holds wrapped data keys and the master key that unwraps them.
type KMS struct {
	mu       sync.Mutex
	master   []byte
	wrapped  map[string][]byte // workload_id -> AES-GCM wrapped key
	audit    []Decision
	auditMax int
}

// New builds a KMS around the given 32-byte master key with no enrolled keys.
func New(masterKey []byte) (*KMS, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(masterKey))
	}
	return &KMS{master: append([]byte(nil), masterKey...), wrapped: map[string][]byte{}, auditMax: 200}, nil
}

// NewFromFile loads wrapped keys from a JSON file of the form
// {"workload_id": "<base64 of wrapped blob>"} and builds a KMS around the
// given 32-byte master key.
func NewFromFile(keysPath string, masterKey []byte) (*KMS, error) {
	k, err := New(masterKey)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(keysPath)
	if err != nil {
		return nil, fmt.Errorf("read keys file: %w", err)
	}
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse keys file: %w", err)
	}
	for id, b64 := range raw {
		blob, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("keys[%s]: invalid base64: %w", id, err)
		}
		k.wrapped[id] = blob
	}
	return k, nil
}

// Wrap seals a data key for a workload with the master key (used by the
// keygen helper; not part of the release path).
func (k *KMS) Wrap(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.master)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// ReleaseRequest is the outcome of a key-release attempt.
type ReleaseRequest struct {
	Granted bool     `json:"granted"`
	KeyB64  string   `json:"key_b64,omitempty"` // base64 plaintext data key, granted only
	Binding string   `json:"binding,omitempty"` // HMAC(workload_id|nonce) proving session binding
	Reasons []string `json:"reasons,omitempty"`
}

// Release evaluates the composite verdict and, on success, unwraps the
// workload's data key. Every call is audited.
func (k *KMS) Release(req *evidence.AttestationRequest, v policy.CompositeVerdict) ReleaseRequest {
	k.mu.Lock()
	defer k.mu.Unlock()

	decision := Decision{Time: time.Now().UTC(), WorkloadID: req.WorkloadID, Granted: false}
	out := ReleaseRequest{Granted: false}

	deny := func(reasons ...string) ReleaseRequest {
		out.Reasons = reasons
		decision.Reasons = reasons
		k.appendAudit(decision)
		return out
	}

	if !v.Pass {
		return deny(append([]string{"composite attestation failed"}, v.Reasons...)...)
	}
	blob, ok := k.wrapped[req.WorkloadID]
	if !ok {
		return deny("no data key enrolled for workload " + req.WorkloadID)
	}
	plain, err := k.unwrap(blob)
	if err != nil {
		return deny("key unwrap failed: " + err.Error())
	}
	out.Granted = true
	out.KeyB64 = base64.StdEncoding.EncodeToString(plain)
	out.Binding = sessionBinding(k.master, req.WorkloadID, req.CPU.SessionNonce)
	decision.Granted = true
	k.appendAudit(decision)
	return out
}

// Enroll registers a wrapped data key for a workload (demo/testing helper).
func (k *KMS) Enroll(workloadID string, wrapped []byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.wrapped[workloadID] = wrapped
}

// Audit returns a copy of recent decisions, newest last.
func (k *KMS) Audit() []Decision {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]Decision, len(k.audit))
	copy(out, k.audit)
	return out
}

func (k *KMS) appendAudit(d Decision) {
	k.audit = append(k.audit, d)
	if len(k.audit) > k.auditMax {
		k.audit = k.audit[len(k.audit)-k.auditMax:]
	}
}

func (k *KMS) unwrap(blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.master)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, fmt.Errorf("wrapped blob too short")
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], nil)
}

// sessionBinding produces an HMAC over workload_id and session nonce with
// the master key, letting the workload prove the released key is bound to
// its attested session.
func sessionBinding(master []byte, workloadID, nonce string) string {
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte(workloadID + "|" + nonce))
	return hex.EncodeToString(mac.Sum(nil))
}

// MasterKeyFromEnv reads KMS_MASTER_KEY (64 hex chars = 32 bytes).
func MasterKeyFromEnv() ([]byte, error) {
	raw := os.Getenv("KMS_MASTER_KEY")
	if raw == "" {
		return nil, fmt.Errorf("KMS_MASTER_KEY is not set")
	}
	b, err := hex.DecodeString(raw)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("KMS_MASTER_KEY must be 64 hex chars (32 bytes)")
	}
	return b, nil
}
