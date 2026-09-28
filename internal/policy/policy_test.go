package policy

import (
	"testing"
	"time"

	"github.com/PeaceXXX/composite-attestation-combiner/internal/evidence"
	"github.com/PeaceXXX/composite-attestation-combiner/internal/verifier"
)

// passVerifier and failVerifier are test doubles for verifier.Verifier,
// letting policy tests focus on the combiner rather than the real verifiers.
type passVerifier struct{}

func (passVerifier) Verify(*evidence.AttestationRequest) verifier.SourceVerdict {
	return verifier.SourceVerdict{Source: "stub", Pass: true}
}

type failVerifier struct{}

func (failVerifier) Verify(*evidence.AttestationRequest) verifier.SourceVerdict {
	return verifier.SourceVerdict{Source: "stub", Pass: false, Reasons: []string{"stub failure"}}
}

func testCombiner(now time.Time) Combiner {
	return Combiner{
		CPU:             passVerifier{},
		GPU:             passVerifier{},
		FreshnessWindow: 5 * time.Minute,
		Now:             func() time.Time { return now },
	}
}

func baseRequest(now time.Time) *evidence.AttestationRequest {
	return &evidence.AttestationRequest{
		WorkloadID: "w1", UsesGPU: true, IssuedAt: now.Unix(),
		CPU: evidence.CPUQuote{
			QuoteVersion: 4, TeeType: "tdx", TCBVersion: "2.1.0",
			TDAttributes: "0x11", MRTD: "aa",
			RTMR0: "bb", RTMR1: "cc", RTMR2: "dd", RTMR3: "ee",
			SessionNonce: "57715a5b540e982a377b70434521b9af",
		},
		GPU: &evidence.GPUEvidence{
			DeviceModel: "H100", DeviceID: "d1", DriverVersion: "550.127.05",
			VBIOSVersion: "1.0", Firmware: map[string]string{"vbios": "ff"},
			SessionNonce: "57715a5b540e982a377b70434521b9af",
		},
	}
}

func TestCombinePass(t *testing.T) {
	now := time.Now()
	v := testCombiner(now).Combine(baseRequest(now))
	if !v.Pass {
		t.Fatalf("expected pass, got %v", v.Reasons)
	}
	if v.Score != 1.0 {
		t.Fatalf("expected score 1.0, got %v", v.Score)
	}
	if len(v.Sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(v.Sources))
	}
}

func TestCombineStale(t *testing.T) {
	now := time.Now()
	req := baseRequest(now.Add(-time.Hour))
	if v := testCombiner(now).Combine(req); v.Pass {
		t.Fatal("expected stale evidence to fail")
	}
}

func TestCombineNonceMismatch(t *testing.T) {
	now := time.Now()
	req := baseRequest(now)
	req.GPU.SessionNonce = "fbd7a576bb2332c2846aad8723bfd545"
	if v := testCombiner(now).Combine(req); v.Pass {
		t.Fatal("expected nonce splice to fail")
	}
}

func TestCombineFutureIssued(t *testing.T) {
	now := time.Now()
	req := baseRequest(now.Add(time.Hour))
	if v := testCombiner(now).Combine(req); v.Pass {
		t.Fatal("expected future-dated evidence to fail")
	}
}

func TestCombineCPUOnlySkipsGPU(t *testing.T) {
	now := time.Now()
	req := baseRequest(now)
	req.UsesGPU = false
	req.GPU = nil
	c := testCombiner(now)
	c.GPU = failVerifier{} // would fail if it were evaluated
	v := c.Combine(req)
	if !v.Pass {
		t.Fatalf("expected pass for cpu-only workload, got %v", v.Reasons)
	}
	if len(v.Sources) != 1 {
		t.Fatalf("expected 1 source for cpu-only, got %d", len(v.Sources))
	}
}

func TestCombineScoreReflectsPartial(t *testing.T) {
	now := time.Now()
	c := testCombiner(now)
	c.GPU = failVerifier{}
	v := c.Combine(baseRequest(now))
	if v.Pass {
		t.Fatal("expected overall failure when gpu fails")
	}
	if v.Score != 0.5 {
		t.Fatalf("expected score 0.5, got %v", v.Score)
	}
}

func TestCombineStructuralErrorsShortCircuit(t *testing.T) {
	now := time.Now()
	req := baseRequest(now)
	req.WorkloadID = ""
	v := testCombiner(now).Combine(req)
	if v.Pass {
		t.Fatal("expected failure on structural error")
	}
	if v.Score != 0 {
		t.Fatalf("expected score 0 on structural error, got %v", v.Score)
	}
	if len(v.Sources) != 0 {
		t.Fatal("verifiers must not run after structural failure")
	}
}
