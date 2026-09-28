package evidence

import "testing"

func TestEqualHex(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0xA1b2", "a1b2", true},
		{"A1B2", "a1b2", true},
		{"0xa1b2", "a1b3", false},
		{"zz", "zz", false}, // invalid hex
		{"a1b2", "a1b200", false},
	}
	for _, c := range cases {
		if got := EqualHex(c.a, c.b); got != c.want {
			t.Errorf("EqualHex(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}

func goodCPU() *CPUQuote {
	return &CPUQuote{
		QuoteVersion: 4, TeeType: "tdx", TCBVersion: "2.1.0",
		TDAttributes: "0x11", MRTD: "aa", RTMR0: "bb", RTMR1: "cc",
		RTMR2: "dd", RTMR3: "ee", SessionNonce: "57715a5b540e982a377b70434521b9af",
	}
}

func TestCPUValidate(t *testing.T) {
	if p := goodCPU().Validate(); len(p) != 0 {
		t.Fatalf("expected no problems, got %v", p)
	}
	bad := goodCPU()
	bad.MRTD = "not-hex!!"
	if p := bad.Validate(); len(p) == 0 {
		t.Fatal("expected problems for invalid hex")
	}
	bad2 := goodCPU()
	bad2.SessionNonce = ""
	if p := bad2.Validate(); len(p) == 0 {
		t.Fatal("expected problems for missing nonce")
	}
	bad3 := goodCPU()
	bad3.SessionNonce = "tooshort"
	if p := bad3.Validate(); len(p) == 0 {
		t.Fatal("expected problems for short nonce")
	}
}

func TestRequestValidateGPURequired(t *testing.T) {
	r := &AttestationRequest{WorkloadID: "w", UsesGPU: true, IssuedAt: 1, CPU: *goodCPU()}
	if p := r.Validate(); len(p) == 0 {
		t.Fatal("expected problem: uses_gpu=true but no gpu evidence")
	}
	r.GPU = &GPUEvidence{
		DeviceModel: "H100", DeviceID: "d", DriverVersion: "1.0",
		Firmware: map[string]string{"vbios": "aa"}, SessionNonce: "57715a5b540e982a377b70434521b9af",
	}
	if p := r.Validate(); len(p) != 0 {
		t.Fatalf("expected no problems, got %v", p)
	}
	// GPU evidence present but uses_gpu=false is also a structural error.
	r.UsesGPU = false
	if p := r.Validate(); len(p) == 0 {
		t.Fatal("expected problem: gpu evidence with uses_gpu=false")
	}
}
