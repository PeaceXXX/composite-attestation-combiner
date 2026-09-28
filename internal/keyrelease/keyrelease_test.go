package keyrelease

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/PeaceXXX/composite-attestation-combiner/internal/evidence"
	"github.com/PeaceXXX/composite-attestation-combiner/internal/policy"
)

func testKMS(t *testing.T) (*KMS, []byte) {
	t.Helper()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	k, err := New(master)
	if err != nil {
		t.Fatal(err)
	}
	return k, master
}

func enrollKey(t *testing.T, k *KMS, workload string) []byte {
	t.Helper()
	plain := make([]byte, 32)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	blob, err := k.Wrap(plain)
	if err != nil {
		t.Fatal(err)
	}
	k.Enroll(workload, blob)
	return plain
}

func passVerdict() policy.CompositeVerdict {
	return policy.CompositeVerdict{Pass: true, Score: 1.0}
}

func testRequest() *evidence.AttestationRequest {
	return &evidence.AttestationRequest{
		WorkloadID: "w1", UsesGPU: false, IssuedAt: 1000,
		CPU: evidence.CPUQuote{
			QuoteVersion: 4, TeeType: "tdx", TCBVersion: "2.1.0",
			TDAttributes: "0x11", MRTD: "aa",
			RTMR0: "bb", RTMR1: "cc", RTMR2: "dd", RTMR3: "ee",
			SessionNonce: "n1",
		},
	}
}

func TestReleaseGrantsOnPass(t *testing.T) {
	k, _ := testKMS(t)
	plain := enrollKey(t, k, "w1")
	rel := k.Release(testRequest(), passVerdict())
	if !rel.Granted {
		t.Fatalf("expected grant, got %v", rel.Reasons)
	}
	got, err := base64.StdEncoding.DecodeString(rel.KeyB64)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatal("released key does not match enrolled key")
	}
	if rel.Binding == "" {
		t.Fatal("expected non-empty session binding")
	}
	audit := k.Audit()
	if len(audit) != 1 || !audit[0].Granted {
		t.Fatalf("expected one granted audit entry, got %+v", audit)
	}
}

func TestReleaseDeniesOnFailedVerdict(t *testing.T) {
	k, _ := testKMS(t)
	enrollKey(t, k, "w1")
	rel := k.Release(testRequest(), policy.CompositeVerdict{Pass: false, Score: 0.5, Reasons: []string{"gpu verification failed"}})
	if rel.Granted {
		t.Fatal("expected denial")
	}
	if len(rel.Reasons) == 0 {
		t.Fatal("expected denial reasons")
	}
	if rel.KeyB64 != "" {
		t.Fatal("denied release must not include a key")
	}
	audit := k.Audit()
	if len(audit) != 1 || audit[0].Granted {
		t.Fatalf("expected one denied audit entry, got %+v", audit)
	}
}

func TestReleaseDeniesUnknownWorkload(t *testing.T) {
	k, _ := testKMS(t)
	req := testRequest()
	req.WorkloadID = "unknown"
	if rel := k.Release(req, passVerdict()); rel.Granted {
		t.Fatal("expected denial for unknown workload")
	}
}

func TestReleaseDeniesOnCorruptBlob(t *testing.T) {
	k, _ := testKMS(t)
	k.Enroll("w1", []byte("too-short"))
	if rel := k.Release(testRequest(), passVerdict()); rel.Granted {
		t.Fatal("expected denial for corrupt wrapped blob")
	}
}

func TestMasterKeyFromEnvMissing(t *testing.T) {
	t.Setenv("KMS_MASTER_KEY", "")
	if _, err := MasterKeyFromEnv(); err == nil {
		t.Fatal("expected error when KMS_MASTER_KEY unset")
	}
	t.Setenv("KMS_MASTER_KEY", "deadbeef")
	if _, err := MasterKeyFromEnv(); err == nil {
		t.Fatal("expected error for short key")
	}
}
