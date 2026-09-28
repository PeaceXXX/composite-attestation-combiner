// Package reference loads the golden reference manifest: the known-good
// measurements and minimum versions that evidence is verified against.
//
// In production this data would be provisioned by the hardware vendor or
// the workload owner and signed; here it is a local JSON file so the
// verifier logic can be exercised without any external dependency.
package reference

import (
	"encoding/json"
	"fmt"
	"os"
)

// Manifest is the full set of golden values.
type Manifest struct {
	CPU                    CPUReference `json:"cpu"`
	GPU                    GPUReference `json:"gpu"`
	FreshnessWindowSeconds int64        `json:"freshness_window_seconds"`
}

// CPUReference holds golden values for TDX evidence.
type CPUReference struct {
	MinTCBVersion        string            `json:"min_tcb_version"`
	AllowedTeeTypes      []string          `json:"allowed_tee_types"`
	GoldenMRTD           string            `json:"golden_mrtd"`
	GoldenRTMR           map[string]string `json:"golden_rtmr"`            // "rtmr0".."rtmr3"
	RequiredTDAttributes string            `json:"required_td_attributes"` // hex bitmask; evidence must include all these bits
}

// GPUReference holds golden values for GPU evidence, per device model.
type GPUReference struct {
	AllowedModels    []string                     `json:"allowed_models"`
	MinDriverVersion string                       `json:"min_driver_version"`
	GoldenFirmware   map[string]map[string]string `json:"golden_firmware"` // model -> component -> hex
}

// Load reads a manifest from a JSON file.
func Load(path string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read manifest %s: %w", path, err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", path, err)
	}
	if m.FreshnessWindowSeconds <= 0 {
		m.FreshnessWindowSeconds = 300
	}
	return &m, nil
}

// CompareVersions compares dotted versions ("550.54.15").
// Returns -1, 0, +1 for a<b, a==b, a>b. Non-numeric segments are ignored.
func CompareVersions(a, b string) int {
	pa, pb := splitVer(a), splitVer(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var va, vb int
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		if va < vb {
			return -1
		}
		if va > vb {
			return 1
		}
	}
	return 0
}

func splitVer(s string) []int {
	var out []int
	cur := 0
	seen := false
	for _, r := range s {
		if r >= '0' && r <= '9' {
			cur = cur*10 + int(r-'0')
			seen = true
		} else if r == '.' && seen {
			out = append(out, cur)
			cur = 0
			seen = false
		} else if seen {
			out = append(out, cur)
			cur = 0
			seen = false
		}
	}
	if seen {
		out = append(out, cur)
	}
	return out
}
