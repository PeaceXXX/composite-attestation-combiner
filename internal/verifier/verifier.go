// Package verifier checks each evidence source against the golden
// reference manifest. Each verifier is source-specific (CPU vs GPU) and
// returns a SourceVerdict; the policy package decides how to combine them.
package verifier

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/PeaceXXX/composite-attestation-combiner/internal/evidence"
	"github.com/PeaceXXX/composite-attestation-combiner/internal/reference"
)

// SourceVerdict is the outcome of verifying one evidence source.
type SourceVerdict struct {
	Source  string   `json:"source"` // "cpu" or "gpu"
	Pass    bool     `json:"pass"`
	Reasons []string `json:"reasons,omitempty"`
}

// Verifier verifies one evidence source.
type Verifier interface {
	Verify(req *evidence.AttestationRequest) SourceVerdict
}

// CPUVerifier verifies TDX CPU quotes against the CPU reference values.
type CPUVerifier struct{ Ref *reference.CPUReference }

// Verify checks TEE type, TCB version floor, TD attributes and all
// measurements against the golden reference.
func (v CPUVerifier) Verify(req *evidence.AttestationRequest) SourceVerdict {
	vd := SourceVerdict{Source: "cpu", Pass: true}
	q := req.CPU
	fail := func(format string, args ...interface{}) {
		vd.Pass = false
		vd.Reasons = append(vd.Reasons, fmt.Sprintf(format, args...))
	}

	allowed := false
	for _, t := range v.Ref.AllowedTeeTypes {
		if strings.EqualFold(t, q.TeeType) {
			allowed = true
			break
		}
	}
	if !allowed {
		fail("tee_type %q not in allowed list %v", q.TeeType, v.Ref.AllowedTeeTypes)
	}

	if reference.CompareVersions(q.TCBVersion, v.Ref.MinTCBVersion) < 0 {
		fail("tcb_version %s below minimum %s", q.TCBVersion, v.Ref.MinTCBVersion)
	}

	if !attributesInclude(q.TDAttributes, v.Ref.RequiredTDAttributes) {
		fail("td_attributes %s missing required bits %s", q.TDAttributes, v.Ref.RequiredTDAttributes)
	}

	if !evidence.EqualHex(q.MRTD, v.Ref.GoldenMRTD) {
		fail("mrtd does not match golden measurement")
	}
	rtmrs := map[string]string{"rtmr0": q.RTMR0, "rtmr1": q.RTMR1, "rtmr2": q.RTMR2, "rtmr3": q.RTMR3}
	for name, got := range rtmrs {
		want, ok := v.Ref.GoldenRTMR[name]
		if !ok {
			fail("no golden value for %s", name)
			continue
		}
		if !evidence.EqualHex(got, want) {
			fail("%s does not match golden measurement", name)
		}
	}
	return vd
}

// GPUVerifier verifies GPU evidence against the per-model reference values.
type GPUVerifier struct{ Ref *reference.GPUReference }

// Verify checks device model allowlist, driver version floor and firmware
// measurements against the golden values for the reported model.
func (v GPUVerifier) Verify(req *evidence.AttestationRequest) SourceVerdict {
	vd := SourceVerdict{Source: "gpu", Pass: true}
	if req.GPU == nil {
		vd.Pass = false
		vd.Reasons = append(vd.Reasons, "gpu evidence missing")
		return vd
	}
	g := req.GPU
	fail := func(format string, args ...interface{}) {
		vd.Pass = false
		vd.Reasons = append(vd.Reasons, fmt.Sprintf(format, args...))
	}

	allowed := false
	for _, m := range v.Ref.AllowedModels {
		if strings.EqualFold(m, g.DeviceModel) {
			allowed = true
			break
		}
	}
	if !allowed {
		fail("device_model %q not in allowed list %v", g.DeviceModel, v.Ref.AllowedModels)
	}

	if reference.CompareVersions(g.DriverVersion, v.Ref.MinDriverVersion) < 0 {
		fail("driver_version %s below minimum %s", g.DriverVersion, v.Ref.MinDriverVersion)
	}

	golden, ok := v.Ref.GoldenFirmware[strings.ToUpper(g.DeviceModel)]
	if !ok {
		fail("no golden firmware values for model %q", g.DeviceModel)
		return vd
	}
	for comp, want := range golden {
		got, present := g.Firmware[comp]
		if !present {
			fail("firmware component %q missing from evidence", comp)
			continue
		}
		if !evidence.EqualHex(got, want) {
			fail("firmware[%s] does not match golden measurement", comp)
		}
	}
	return vd
}

// attributesInclude reports whether the hex bitmask have includes every bit
// set in want. Both tolerate 0x prefixes.
func attributesInclude(have, want string) bool {
	trim := func(s string) string {
		s = strings.TrimSpace(s)
		s = strings.TrimPrefix(s, "0x")
		s = strings.TrimPrefix(s, "0X")
		return s
	}
	h, errH := strconv.ParseUint(trim(have), 16, 64)
	w, errW := strconv.ParseUint(trim(want), 16, 64)
	if errH != nil || errW != nil {
		return false
	}
	return h&w == w
}
