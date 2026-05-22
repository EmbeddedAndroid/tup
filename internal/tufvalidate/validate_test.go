package tufvalidate

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeTufd produces a minimal valid v1 chain we can validate against
// without depending on the full tufd stack. Used to lock in the
// canonical-JSON + ed25519 contract of the validator.
func fakeTufd(t *testing.T) *httptest.Server {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	keyID := sha256Hex(pubDER)

	rootPayload := map[string]any{
		"_type": "Root", "version": 1,
		"keys": map[string]any{keyID: map[string]any{
			"keytype": "ed25519", "scheme": "ed25519",
			"keyval": map[string]any{"public": pubPEM},
		}},
		"roles": map[string]any{
			"Root":      map[string]any{"keyids": []string{keyID}, "threshold": 1},
			"Targets":   map[string]any{"keyids": []string{keyID}, "threshold": 1},
			"Snapshot":  map[string]any{"keyids": []string{keyID}, "threshold": 1},
			"Timestamp": map[string]any{"keyids": []string{keyID}, "threshold": 1},
		},
	}
	rootCanon := mustCanon(rootPayload)
	rootEnv := envelope(rootCanon, keyID, ed25519.Sign(priv, rootCanon))

	tgtPayload := map[string]any{
		"_type": "Targets", "version": 1,
		"targets": map[string]any{
			"lmp-42": map[string]any{
				"length": 0,
				"hashes": map[string]any{"sha256": "abc123"},
				"custom": map[string]any{"name": "lmp", "version": "42"},
			},
		},
	}
	tgtCanon := mustCanon(tgtPayload)
	tgtEnv := envelope(tgtCanon, keyID, ed25519.Sign(priv, tgtCanon))

	snapPayload := map[string]any{
		"_type": "Snapshot", "version": 1,
		"meta": map[string]any{"targets.json": map[string]any{"version": 1}},
	}
	snapCanon := mustCanon(snapPayload)
	snapEnv := envelope(snapCanon, keyID, ed25519.Sign(priv, snapCanon))

	tsPayload := map[string]any{
		"_type": "Timestamp", "version": 1000,
		"meta": map[string]any{"snapshot.json": map[string]any{
			"hashes":  map[string]any{"sha256": sha256Hex(snapEnv)},
			"length":  len(snapEnv),
			"version": 1,
		}},
	}
	tsCanon := mustCanon(tsPayload)
	tsEnv := envelope(tsCanon, keyID, ed25519.Sign(priv, tsCanon))

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/user_repo/demo/1.root.json",
		func(w http.ResponseWriter, _ *http.Request) { w.Write(rootEnv) })
	mux.HandleFunc("/api/v1/user_repo/demo/2.root.json",
		func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	mux.HandleFunc("/api/v1/user_repo/demo/targets.json",
		func(w http.ResponseWriter, _ *http.Request) { w.Write(tgtEnv) })
	mux.HandleFunc("/api/v1/user_repo/demo/snapshot.json",
		func(w http.ResponseWriter, _ *http.Request) { w.Write(snapEnv) })
	mux.HandleFunc("/api/v1/user_repo/demo/timestamp.json",
		func(w http.ResponseWriter, _ *http.Request) { w.Write(tsEnv) })
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestValidate_HappyPath(t *testing.T) {
	srv := fakeTufd(t)
	r, err := Validate(srv.URL, "demo")
	if err != nil {
		t.Fatalf("validate failed: %v\nresult: %+v", err, r)
	}
	if r.LatestRoot != 1 {
		t.Errorf("LatestRoot = %d, want 1", r.LatestRoot)
	}
	if len(r.RootChain) != 1 || r.RootChain[0].Status != "ok" {
		t.Errorf("root chain = %+v", r.RootChain)
	}
	if r.Timestamp.Status != "ok" || r.Snapshot.Status != "ok" || r.Targets.Status != "ok" {
		t.Errorf("role verify: ts=%+v snap=%+v tgt=%+v", r.Timestamp, r.Snapshot, r.Targets)
	}
	if r.TargetCount != 1 {
		t.Errorf("targets count = %d, want 1", r.TargetCount)
	}
}

func TestValidate_404On1RootJson(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	_, err := Validate(srv.URL, "missing")
	if err == nil {
		t.Fatal("expected error for missing 1.root.json")
	}
}

// TestValidate_RejectsTamperedSnapshot: if snapshot bytes don't match
// what timestamp.meta declares, the validator MUST refuse. Guards
// against silent tampering between sign-time + serve-time.
func TestValidate_RejectsTamperedSnapshot(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	keyID := sha256Hex(pubDER)
	rootPayload := map[string]any{
		"_type": "Root", "version": 1,
		"keys": map[string]any{keyID: map[string]any{
			"keytype": "ed25519", "scheme": "ed25519",
			"keyval": map[string]any{"public": pubPEM},
		}},
		"roles": map[string]any{
			"Root":      map[string]any{"keyids": []string{keyID}, "threshold": 1},
			"Snapshot":  map[string]any{"keyids": []string{keyID}, "threshold": 1},
			"Timestamp": map[string]any{"keyids": []string{keyID}, "threshold": 1},
			"Targets":   map[string]any{"keyids": []string{keyID}, "threshold": 1},
		},
	}
	rootCanon := mustCanon(rootPayload)
	rootEnv := envelope(rootCanon, keyID, ed25519.Sign(priv, rootCanon))

	snapACanon := mustCanon(map[string]any{
		"_type": "Snapshot", "version": 1,
		"meta": map[string]any{"targets.json": map[string]any{"version": 1}},
	})
	snapA := envelope(snapACanon, keyID, ed25519.Sign(priv, snapACanon))
	snapBCanon := mustCanon(map[string]any{
		"_type": "Snapshot", "version": 2,
		"meta": map[string]any{"targets.json": map[string]any{"version": 1}},
	})
	snapB := envelope(snapBCanon, keyID, ed25519.Sign(priv, snapBCanon))
	// timestamp references snapA, server returns snapB.
	tsCanon := mustCanon(map[string]any{
		"_type": "Timestamp", "version": 1000,
		"meta": map[string]any{"snapshot.json": map[string]any{
			"hashes": map[string]any{"sha256": sha256Hex(snapA)},
			"length": len(snapA), "version": 1,
		}},
	})
	tsEnv := envelope(tsCanon, keyID, ed25519.Sign(priv, tsCanon))

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/user_repo/demo/1.root.json",
		func(w http.ResponseWriter, _ *http.Request) { w.Write(rootEnv) })
	mux.HandleFunc("/api/v1/user_repo/demo/2.root.json",
		func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	mux.HandleFunc("/api/v1/user_repo/demo/snapshot.json",
		func(w http.ResponseWriter, _ *http.Request) { w.Write(snapB) })
	mux.HandleFunc("/api/v1/user_repo/demo/timestamp.json",
		func(w http.ResponseWriter, _ *http.Request) { w.Write(tsEnv) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r, err := Validate(srv.URL, "demo")
	if err == nil {
		t.Fatalf("validator accepted tampered snapshot: %+v", r)
	}
	if !strings.Contains(err.Error(), "snapshot") {
		t.Errorf("error doesn't mention snapshot: %v", err)
	}
}

// --- shared test helpers ---

func mustCanon(v any) []byte {
	b, _ := json.Marshal(v)
	out, err := canonicalJSON(b)
	if err != nil {
		panic(err)
	}
	return out
}

func envelope(signedBytes []byte, keyID string, sig []byte) []byte {
	env := map[string]any{
		"signatures": []map[string]string{{"keyid": keyID, "sig": hex.EncodeToString(sig)}},
		"signed":     json.RawMessage(signedBytes),
	}
	b, _ := json.Marshal(env)
	return b
}
