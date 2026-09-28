// Command demo runs the full composite-attestation flow end to end against
// the bundled sample evidence, no server required.
//
//	Usage:
//	  demo                  run all scenarios and print a results table
//	  demo --print-request <name>
//	                        print one sample as JSON with a fresh issued_at,
//	                        ready to POST to a running server
//	  demo --list           list available samples
//
// Scenarios: pass, tampered-cpu, tampered-gpu, nonce-splice, stale, cpu-only.
package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/PeaceXXX/composite-attestation-combiner/internal/evidence"
	"github.com/PeaceXXX/composite-attestation-combiner/internal/keyrelease"
	"github.com/PeaceXXX/composite-attestation-combiner/internal/policy"
	"github.com/PeaceXXX/composite-attestation-combiner/internal/reference"
	"github.com/PeaceXXX/composite-attestation-combiner/internal/verifier"
)

var scenarioOrder = []string{"pass", "tampered-cpu", "tampered-gpu", "nonce-splice", "stale", "cpu-only"}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--list" {
		for _, s := range scenarioOrder {
			fmt.Println(s)
		}
		return
	}
	manifest, err := reference.Load("data/reference-manifest.json")
	if err != nil {
		fatal(err)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		fatal(err)
	}
	kms, err := keyrelease.New(master)
	if err != nil {
		fatal(err)
	}
	// Enroll one data key per workload used by the samples.
	for _, wl := range []string{"inference-worker-01"} {
		plain := make([]byte, 32)
		if _, err := rand.Read(plain); err != nil {
			fatal(err)
		}
		blob, err := kms.Wrap(plain)
		if err != nil {
			fatal(err)
		}
		kms.Enroll(wl, blob)
	}
	combiner := policy.Combiner{
		CPU:             verifier.CPUVerifier{Ref: &manifest.CPU},
		GPU:             verifier.GPUVerifier{Ref: &manifest.GPU},
		FreshnessWindow: time.Duration(manifest.FreshnessWindowSeconds) * time.Second,
	}

	if len(os.Args) == 3 && os.Args[1] == "--print-request" {
		req := loadSample(os.Args[2], time.Now())
		data, _ := json.MarshalIndent(req, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("%-14s %-8s %-6s %s\n", "SCENARIO", "VERDICT", "SCORE", "NOTES")
	for _, name := range scenarioOrder {
		req := loadSample(name, time.Now())
		v := combiner.Combine(req)
		rel := kms.Release(req, v)
		verdict := "DENY"
		if rel.Granted {
			verdict = "GRANT"
		}
		notes := "-"
		if len(v.Reasons) > 0 {
			notes = v.Reasons[0]
			if len(v.Reasons) > 1 {
				notes += fmt.Sprintf(" (+%d more)", len(v.Reasons)-1)
			}
		}
		fmt.Printf("%-14s %-8s %-6.2f %s\n", name, verdict, v.Score, notes)
	}
}

// loadSample reads a sample and normalizes issued_at: every scenario except
// "stale" gets a fresh timestamp; "stale" is backdated past the freshness
// window so the freshness check can be demonstrated.
func loadSample(name string, now time.Time) *evidence.AttestationRequest {
	req, err := evidence.LoadRequest(filepath.Join("data", "samples", name+".json"))
	if err != nil {
		fatal(err)
	}
	if name == "stale" {
		req.IssuedAt = now.Add(-1 * time.Hour).Unix()
	} else {
		req.IssuedAt = now.Unix()
	}
	return req
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "demo:", err)
	os.Exit(1)
}
