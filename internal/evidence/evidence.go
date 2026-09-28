// Package evidence defines the attestation evidence model.
//
// The model mirrors the *shape* of real-world confidential-computing
// evidence — an Intel TDX quote's TD report body and an NVIDIA GPU
// attestation report — but every field here is carried as JSON and every
// measurement value in the sample data is fictional. This package performs
// structure validation only; semantic verification lives in internal/verifier.
package evidence

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// MinSessionNonceLen is the minimum accepted session_nonce length in
// characters. A nonce shorter than this carries too little entropy to bind
// CPU and GPU evidence to the same session, so it is rejected structurally.
const MinSessionNonceLen = 16

// CPUQuote is a simplified, JSON-carried representation of a TDX quote's
// report body: TCB version, TD attributes and the MRTD/RTMR measurement
// registers. Hex strings are expected to be even-length and lowercase.
type CPUQuote struct {
	QuoteVersion uint16 `json:"quote_version"`
	TeeType      string `json:"tee_type"`      // expected: "tdx"
	TCBVersion   string `json:"tcb_version"`   // dotted, e.g. "2.1.0"
	TDAttributes string `json:"td_attributes"` // hex bitmask, e.g. "0x00000010"
	MRTD         string `json:"mrtd"`
	RTMR0        string `json:"rtmr0"`
	RTMR1        string `json:"rtmr1"`
	RTMR2        string `json:"rtmr2"`
	RTMR3        string `json:"rtmr3"`
	SessionNonce string `json:"session_nonce"` // binds CPU and GPU evidence together
}

// GPUEvidence is a simplified, JSON-carried representation of a GPU
// attestation report (driver + firmware measurements for one device).
type GPUEvidence struct {
	DeviceModel   string            `json:"device_model"` // e.g. "H100"
	DeviceID      string            `json:"device_id"`
	DriverVersion string            `json:"driver_version"`
	VBIOSVersion  string            `json:"vbios_version"`
	Firmware      map[string]string `json:"firmware"` // component name -> hex measurement
	SessionNonce  string            `json:"session_nonce"`
}

// AttestationRequest is what a confidential-inference worker submits when it
// wants the key-release service to unwrap its model decryption key.
type AttestationRequest struct {
	WorkloadID string       `json:"workload_id"`
	UsesGPU    bool         `json:"uses_gpu"`
	IssuedAt   int64        `json:"issued_at"` // unix seconds; freshness-checked
	CPU        CPUQuote     `json:"cpu"`
	GPU        *GPUEvidence `json:"gpu,omitempty"`
}

// Validate performs structural checks: required fields, hex decodability,
// and internal consistency. It does NOT compare against golden values.
func (r *AttestationRequest) Validate() []string {
	var problems []string
	if strings.TrimSpace(r.WorkloadID) == "" {
		problems = append(problems, "workload_id is required")
	}
	if r.IssuedAt <= 0 {
		problems = append(problems, "issued_at must be a positive unix timestamp")
	}
	for _, p := range r.CPU.Validate() {
		problems = append(problems, "cpu."+p)
	}
	if r.UsesGPU {
		if r.GPU == nil {
			problems = append(problems, "gpu evidence is required when uses_gpu is true")
		} else {
			for _, p := range r.GPU.Validate() {
				problems = append(problems, "gpu."+p)
			}
		}
	} else if r.GPU != nil {
		problems = append(problems, "gpu evidence supplied but uses_gpu is false")
	}
	return problems
}

// Validate checks a CPUQuote's structure.
func (q *CPUQuote) Validate() []string {
	var problems []string
	if q.QuoteVersion == 0 {
		problems = append(problems, "quote_version must be non-zero")
	}
	if q.TeeType == "" {
		problems = append(problems, "tee_type is required")
	}
	if strings.TrimSpace(q.TCBVersion) == "" {
		problems = append(problems, "tcb_version is required")
	}
	if n := strings.TrimSpace(q.SessionNonce); n == "" {
		problems = append(problems, "session_nonce is required")
	} else if len(n) < MinSessionNonceLen {
		problems = append(problems, fmt.Sprintf("session_nonce must be at least %d characters", MinSessionNonceLen))
	}
	hexFields := map[string]string{
		"mrtd": q.MRTD, "rtmr0": q.RTMR0, "rtmr1": q.RTMR1,
		"rtmr2": q.RTMR2, "rtmr3": q.RTMR3,
	}
	for name, v := range hexFields {
		if strings.TrimSpace(v) == "" {
			problems = append(problems, name+" is required")
			continue
		}
		if _, err := hex.DecodeString(normalizeHex(v)); err != nil {
			problems = append(problems, name+" is not valid hex")
		}
	}
	return problems
}

// Validate checks a GPUEvidence's structure.
func (g *GPUEvidence) Validate() []string {
	var problems []string
	if strings.TrimSpace(g.DeviceModel) == "" {
		problems = append(problems, "device_model is required")
	}
	if strings.TrimSpace(g.DeviceID) == "" {
		problems = append(problems, "device_id is required")
	}
	if strings.TrimSpace(g.DriverVersion) == "" {
		problems = append(problems, "driver_version is required")
	}
	if n := strings.TrimSpace(g.SessionNonce); n == "" {
		problems = append(problems, "session_nonce is required")
	} else if len(n) < MinSessionNonceLen {
		problems = append(problems, fmt.Sprintf("session_nonce must be at least %d characters", MinSessionNonceLen))
	}
	if len(g.Firmware) == 0 {
		problems = append(problems, "firmware must contain at least one component measurement")
	}
	for comp, v := range g.Firmware {
		if _, err := hex.DecodeString(normalizeHex(v)); err != nil {
			problems = append(problems, fmt.Sprintf("firmware[%s] is not valid hex", comp))
		}
	}
	return problems
}

// normalizeHex strips a leading 0x and lowercases the value so comparisons
// are insensitive to cosmetic encoding differences.
func normalizeHex(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	return strings.ToLower(s)
}

// EqualHex reports whether two hex strings decode to the same bytes,
// tolerating 0x prefixes and case differences. The comparison runs in
// constant time so measurement checks do not leak a timing oracle.
func EqualHex(a, b string) bool {
	ba, errA := hex.DecodeString(normalizeHex(a))
	bb, errB := hex.DecodeString(normalizeHex(b))
	if errA != nil || errB != nil {
		return false
	}
	return subtle.ConstantTimeCompare(ba, bb) == 1
}

// LoadRequest reads an AttestationRequest from a JSON file.
func LoadRequest(path string) (*AttestationRequest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var r AttestationRequest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &r, nil
}
