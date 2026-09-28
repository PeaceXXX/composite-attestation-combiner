package verifier

import (
	"testing"

	"github.com/PeaceXXX/composite-attestation-combiner/internal/evidence"
	"github.com/PeaceXXX/composite-attestation-combiner/internal/reference"
)

func testManifest() *reference.Manifest {
	return &reference.Manifest{
		CPU: reference.CPUReference{
			MinTCBVersion:        "2.0.0",
			AllowedTeeTypes:      []string{"tdx"},
			GoldenMRTD:           "aa",
			GoldenRTMR:           map[string]string{"rtmr0": "bb", "rtmr1": "cc", "rtmr2": "dd", "rtmr3": "ee"},
			RequiredTDAttributes: "0x10",
		},
		GPU: reference.GPUReference{
			AllowedModels:    []string{"H100"},
			MinDriverVersion: "550.54.15",
			GoldenFirmware:   map[string]map[string]string{"H100": {"vbios": "ff", "fmc": "11"}},
		},
	}
}

func goodRequest() *evidence.AttestationRequest {
	return &evidence.AttestationRequest{
		WorkloadID: "w1", UsesGPU: true, IssuedAt: 1000,
		CPU: evidence.CPUQuote{
			QuoteVersion: 4, TeeType: "tdx", TCBVersion: "2.1.0",
			TDAttributes: "0x11", MRTD: "aa",
			RTMR0: "bb", RTMR1: "cc", RTMR2: "dd", RTMR3: "ee",
			SessionNonce: "n1",
		},
		GPU: &evidence.GPUEvidence{
			DeviceModel: "H100", DeviceID: "d1", DriverVersion: "550.127.05",
			VBIOSVersion: "1.0", Firmware: map[string]string{"vbios": "ff", "fmc": "11"},
			SessionNonce: "n1",
		},
	}
}

func TestCPUVerifier(t *testing.T) {
	m := testManifest()
	v := CPUVerifier{Ref: &m.CPU}
	if vd := v.Verify(goodRequest()); !vd.Pass {
		t.Fatalf("expected pass, got %v", vd.Reasons)
	}
	cases := []struct {
		name   string
		mutate func(*evidence.AttestationRequest)
	}{
		{"bad mrtd", func(r *evidence.AttestationRequest) { r.CPU.MRTD = "00" }},
		{"bad rtmr", func(r *evidence.AttestationRequest) { r.CPU.RTMR2 = "00" }},
		{"old tcb", func(r *evidence.AttestationRequest) { r.CPU.TCBVersion = "1.9.0" }},
		{"wrong tee", func(r *evidence.AttestationRequest) { r.CPU.TeeType = "sgx" }},
		{"missing attr bit", func(r *evidence.AttestationRequest) { r.CPU.TDAttributes = "0x01" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := goodRequest()
			c.mutate(r)
			if vd := v.Verify(r); vd.Pass {
				t.Fatalf("expected failure, got pass")
			} else if len(vd.Reasons) == 0 {
				t.Fatal("expected reasons on failure")
			}
		})
	}
}

func TestGPUVerifier(t *testing.T) {
	m := testManifest()
	v := GPUVerifier{Ref: &m.GPU}
	if vd := v.Verify(goodRequest()); !vd.Pass {
		t.Fatalf("expected pass, got %v", vd.Reasons)
	}
	cases := []struct {
		name   string
		mutate func(*evidence.AttestationRequest)
	}{
		{"bad firmware", func(r *evidence.AttestationRequest) { r.GPU.Firmware["fmc"] = "00" }},
		{"missing component", func(r *evidence.AttestationRequest) { delete(r.GPU.Firmware, "vbios") }},
		{"old driver", func(r *evidence.AttestationRequest) { r.GPU.DriverVersion = "535.54.03" }},
		{"disallowed model", func(r *evidence.AttestationRequest) { r.GPU.DeviceModel = "A100" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := goodRequest()
			c.mutate(r)
			if vd := v.Verify(r); vd.Pass {
				t.Fatal("expected failure, got pass")
			}
		})
	}
	// Missing GPU evidence must fail, not panic.
	r := goodRequest()
	r.GPU = nil
	if vd := v.Verify(r); vd.Pass {
		t.Fatal("expected failure for nil gpu evidence")
	}
}
