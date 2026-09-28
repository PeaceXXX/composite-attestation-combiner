package server

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/PeaceXXX/composite-attestation-combiner/internal/evidence"
	"github.com/PeaceXXX/composite-attestation-combiner/internal/keyrelease"
	"github.com/PeaceXXX/composite-attestation-combiner/internal/policy"
	"github.com/PeaceXXX/composite-attestation-combiner/internal/verifier"
)

// testService builds a Service whose CPU verifier always passes and whose
// GPU verifier always fails, so both the grant and deny paths are exercised.
func testService(t *testing.T) *Service {
	t.Helper()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	kms, err := keyrelease.New(master)
	if err != nil {
		t.Fatal(err)
	}
	plain := make([]byte, 32)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	blob, err := kms.Wrap(plain)
	if err != nil {
		t.Fatal(err)
	}
	kms.Enroll("w1", blob)
	return &Service{
		Combiner: policy.Combiner{
			CPU:             passStub{},
			GPU:             failStub{},
			FreshnessWindow: 5 * time.Minute,
		},
		KMS: kms,
	}
}

type passStub struct{}

func (passStub) Verify(*evidence.AttestationRequest) verifier.SourceVerdict {
	return verifier.SourceVerdict{Source: "cpu", Pass: true}
}

type failStub struct{}

func (failStub) Verify(*evidence.AttestationRequest) verifier.SourceVerdict {
	return verifier.SourceVerdict{Source: "gpu", Pass: false, Reasons: []string{"stub: bad gpu"}}
}

func postAttest(t *testing.T, svc *Service, usesGPU bool) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{
		"workload_id": "w1",
		"uses_gpu":    usesGPU,
		"issued_at":   time.Now().Unix(),
		"cpu": map[string]interface{}{
			"quote_version": 4, "tee_type": "tdx", "tcb_version": "2.1.0",
			"td_attributes": "0x11", "mrtd": "aa",
			"rtmr0": "bb", "rtmr1": "cc", "rtmr2": "dd", "rtmr3": "ee",
			"session_nonce": "57715a5b540e982a377b70434521b9af",
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/attest", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)
	return rec
}

func TestAttestGrantsCPUOnly(t *testing.T) {
	svc := testService(t)
	rec := postAttest(t, svc, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp AttestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Pass || resp.KeyB64 == "" {
		t.Fatalf("expected grant with key, got %+v", resp)
	}
}

func TestAttestDeniesWhenGPUFails(t *testing.T) {
	svc := testService(t)
	// uses_gpu=true pulls in the failing GPU stub.
	body, _ := json.Marshal(map[string]interface{}{
		"workload_id": "w1",
		"uses_gpu":    true,
		"issued_at":   time.Now().Unix(),
		"cpu": map[string]interface{}{
			"quote_version": 4, "tee_type": "tdx", "tcb_version": "2.1.0",
			"td_attributes": "0x11", "mrtd": "aa",
			"rtmr0": "bb", "rtmr1": "cc", "rtmr2": "dd", "rtmr3": "ee",
			"session_nonce": "57715a5b540e982a377b70434521b9af",
		},
		"gpu": map[string]interface{}{
			"device_model": "H100", "device_id": "d1", "driver_version": "550.127.05",
			"vbios_version": "1.0", "firmware": map[string]string{"vbios": "ff"},
			"session_nonce": "57715a5b540e982a377b70434521b9af",
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/attest", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAttestRejectsBadJSON(t *testing.T) {
	svc := testService(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/attest", bytes.NewReader([]byte("{nope")))
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestHealthz(t *testing.T) {
	svc := testService(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/healthz", nil)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestAuditEndpoint(t *testing.T) {
	svc := testService(t)
	postAttest(t, svc, false)
	req := httptest.NewRequest(http.MethodGet, "/v1/audit", nil)
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var out struct {
		Decisions []keyrelease.Decision `json:"decisions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Decisions) != 1 {
		t.Fatalf("expected 1 audit decision, got %d", len(out.Decisions))
	}
}
