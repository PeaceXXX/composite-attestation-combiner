// Command keygen provisions the demo KMS: it prints a fresh random 32-byte
// master key (set as KMS_MASTER_KEY) and writes data/keys.json containing
// one AES-GCM-wrapped data key per workload id given on the command line.
//
// This is a demo-provisioning helper only. In production, keys would be
// generated and wrapped inside an HSM and never touch a developer laptop.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/PeaceXXX/composite-attestation-combiner/internal/keyrelease"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: keygen <workload-id> [<workload-id>...]")
		os.Exit(1)
	}
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		fmt.Fprintln(os.Stderr, "rand:", err)
		os.Exit(1)
	}
	kms, err := keyrelease.New(master)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	wrapped := map[string]string{}
	for _, id := range os.Args[1:] {
		plain := make([]byte, 32)
		if _, err := rand.Read(plain); err != nil {
			fmt.Fprintln(os.Stderr, "rand:", err)
			os.Exit(1)
		}
		blob, err := kms.Wrap(plain)
		if err != nil {
			fmt.Fprintln(os.Stderr, "wrap:", err)
			os.Exit(1)
		}
		wrapped[id] = base64.StdEncoding.EncodeToString(blob)
	}
	out := filepath.Join("data", "keys.json")
	data, _ := json.MarshalIndent(wrapped, "", "  ")
	if err := os.WriteFile(out, append(data, '\n'), 0600); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d workload keys)\n", out, len(wrapped))
	fmt.Printf("export KMS_MASTER_KEY=%s\n", hex.EncodeToString(master))
	fmt.Println("NOTE: demo master key — never use in production.")
}
