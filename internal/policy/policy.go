// Package policy combines per-source verdicts into a single composite
// attestation decision. This is the "composite attestation" core: a CPU TEE
// quote and a GPU attestation report are only useful for key release when
// they are evaluated together — with freshness, session binding, and a
// workload-aware requirement set.
package policy

import (
	"time"

	"github.com/PeaceXXX/composite-attestation-combiner/internal/evidence"
	"github.com/PeaceXXX/composite-attestation-combiner/internal/verifier"
)

// CompositeVerdict is the combined outcome for one attestation request.
type CompositeVerdict struct {
	Pass    bool                     `json:"pass"`
	Score   float64                  `json:"score"` // 0..1, weighted fraction of passing sources
	Reasons []string                 `json:"reasons,omitempty"`
	Sources []verifier.SourceVerdict `json:"sources"`
}

// Combiner evaluates a request with the configured verifiers and rules.
type Combiner struct {
	CPU             verifier.Verifier
	GPU             verifier.Verifier
	FreshnessWindow time.Duration
	Now             func() time.Time // injectable clock for tests
}

// Combine runs structure validation, per-source verification, freshness and
// session-binding checks, then merges everything into one verdict.
func (c Combiner) Combine(req *evidence.AttestationRequest) CompositeVerdict {
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	v := CompositeVerdict{Score: 1.0}
	fail := func(reason string) {
		v.Pass = false
		v.Reasons = append(v.Reasons, reason)
	}
	v.Pass = true

	// 1. Structural validation first — garbage evidence never reaches crypto.
	if problems := req.Validate(); len(problems) > 0 {
		v.Pass = false
		v.Score = 0
		v.Reasons = append(v.Reasons, problems...)
		return v
	}

	// 2. Freshness: evidence must be recent to prevent replay.
	issued := time.Unix(req.IssuedAt, 0)
	if age := now.Sub(issued); age < 0 {
		fail("evidence issued in the future")
	} else if age > c.FreshnessWindow {
		fail("evidence is stale (age exceeds freshness window)")
	}

	// 3. Verify each required source.
	required := []verifier.Verifier{c.CPU}
	if req.UsesGPU {
		required = append(required, c.GPU)
	}
	for _, verifier := range required {
		sv := verifier.Verify(req)
		v.Sources = append(v.Sources, sv)
		if !sv.Pass {
			fail(sv.Source + " verification failed")
		}
	}

	// 4. Session binding: CPU and GPU evidence must describe the same
	// session, otherwise an attacker could splice a good GPU report onto a
	// compromised CPU quote (or vice versa).
	if req.UsesGPU && req.GPU != nil {
		if req.CPU.SessionNonce != req.GPU.SessionNonce {
			fail("cpu/gpu session_nonce mismatch: evidence is not bound to the same session")
		}
	}

	// 5. Score = weighted pass fraction over the evaluated sources.
	if len(v.Sources) > 0 {
		passed := 0
		for _, s := range v.Sources {
			if s.Pass {
				passed++
			}
		}
		v.Score = float64(passed) / float64(len(v.Sources))
	}
	return v
}
