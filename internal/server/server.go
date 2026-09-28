// Package server exposes the composite attestation service over HTTP:
//
//	POST /v1/attest  verify evidence, combine verdicts, release key on success
//	GET  /v1/healthz liveness
//	GET  /v1/audit   recent key-release decisions (newest last)
package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/PeaceXXX/composite-attestation-combiner/internal/evidence"
	"github.com/PeaceXXX/composite-attestation-combiner/internal/keyrelease"
	"github.com/PeaceXXX/composite-attestation-combiner/internal/policy"
)

// Service wires the combiner and the KMS together.
type Service struct {
	Combiner policy.Combiner
	KMS      *keyrelease.KMS
}

// AttestResponse is returned for POST /v1/attest.
type AttestResponse struct {
	Pass    bool                         `json:"pass"`
	Score   float64                      `json:"score"`
	KeyB64  string                       `json:"key_b64,omitempty"`
	Binding string                       `json:"binding,omitempty"`
	Reasons []string                     `json:"reasons,omitempty"`
	Sources []verifierSourceVerdictAlias `json:"sources"`
}

// verifierSourceVerdictAlias keeps the JSON shape without importing policy's
// inner type in the signature; it mirrors verifier.SourceVerdict.
type verifierSourceVerdictAlias = struct {
	Source  string   `json:"source"`
	Pass    bool     `json:"pass"`
	Reasons []string `json:"reasons,omitempty"`
}

// Handler builds the HTTP mux.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "time": time.Now().UTC().Format(time.RFC3339)})
	})
	mux.HandleFunc("/v1/attest", s.handleAttest)
	mux.HandleFunc("/v1/audit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"decisions": s.KMS.Audit()})
	})
	return mux
}

func (s *Service) handleAttest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req evidence.AttestationRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
		return
	}

	verdict := s.Combiner.Combine(&req)
	rel := s.KMS.Release(&req, verdict)

	resp := AttestResponse{
		Pass:    rel.Granted,
		Score:   verdict.Score,
		KeyB64:  rel.KeyB64,
		Binding: rel.Binding,
		Reasons: rel.Reasons,
	}
	for _, src := range verdict.Sources {
		resp.Sources = append(resp.Sources, verifierSourceVerdictAlias{
			Source: src.Source, Pass: src.Pass, Reasons: src.Reasons,
		})
	}
	status := http.StatusOK
	if !rel.Granted {
		status = http.StatusForbidden
	}
	writeJSON(w, status, resp)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
