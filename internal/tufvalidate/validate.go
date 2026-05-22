// Package tufvalidate is a minimal Foundries-compatible TUF chain
// walker. We can't use stock python-tuf or go-tuf because they reject
// our wire shape (we emit "_type":"Root" capitalized, the modern TUF
// spec wants lowercase; aktualizr-lite tolerates capitalized but
// stock clients don't).
//
// This is the client-side counterpart to tufd's role serving. Used by
// `tup validate <repo-id>` as an end-to-end smoke + as a useful
// operator tool ("does my namespace's metadata chain hold up to a
// real verifier?").
package tufvalidate

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
)

// Result is what `tup validate` prints. Each role's verification is
// either "ok" with the version it was checked at, or an error.
type Result struct {
	RepoID       string
	LatestRoot   int
	RootChain    []ChainStep
	Timestamp    RoleVerification
	Snapshot     RoleVerification
	Targets      RoleVerification
	TargetCount  int
}

type ChainStep struct {
	Version    int
	KeyID      string
	Signatures int
	// "ok" if both prior + new root sigs verified; otherwise the error
	Status string
}

type RoleVerification struct {
	Version int
	Status  string
}

// Validate walks the chain and runs all the checks. Server must be the
// base URL (e.g. http://localhost:19010), repo is the namespace
// repo_id. Bootstrap is implicit: trust v1's signed payload as the
// initial anchor (the customer-anchored equivalent of TOFU; for true
// security the operator pins v1 out of band).
func Validate(server, repo string) (*Result, error) {
	r := &Result{RepoID: repo}
	cli := &http.Client{}

	// 1. Fetch root v1, use it as trust anchor.
	v1Bytes, status, err := fetchRoot(cli, server, repo, 1)
	if err != nil {
		return nil, fmt.Errorf("fetch 1.root.json: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("1.root.json status %d", status)
	}
	v1Env, v1Root, err := parseRootEnvelope(v1Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse v1: %w", err)
	}
	// Self-verify v1: signatures should validate against the root role's
	// keys per the embedded keys map (this is the "trust on first use"
	// — production should pin the v1 keyid out of band).
	if err := verifyRoleSigs(v1Env, v1Root, "Root"); err != nil {
		r.RootChain = append(r.RootChain, ChainStep{
			Version: 1, KeyID: rootKeyID(v1Root), Signatures: len(v1Env.Signatures),
			Status: "FAIL: " + err.Error(),
		})
		return r, fmt.Errorf("v1 self-verify: %w", err)
	}
	r.RootChain = append(r.RootChain, ChainStep{
		Version: 1, KeyID: rootKeyID(v1Root), Signatures: len(v1Env.Signatures),
		Status: "ok",
	})

	// 2. Walk forward. Each N>=2 must be signed by BOTH the prior
	// root's Root key AND the new root's Root key (rotation co-sign).
	// `latest` is the most-recently-verified root; at end of each
	// iteration we promote the just-verified v=N to latest so v=N+1
	// can verify its prior-key sig against it.
	latest := v1Root
	for v := 2; v <= 1000; v++ {
		body, status, err := fetchRoot(cli, server, repo, v)
		if err != nil {
			return r, fmt.Errorf("fetch %d.root.json: %w", v, err)
		}
		if status == http.StatusNotFound {
			break
		}
		if status != http.StatusOK {
			return r, fmt.Errorf("%d.root.json status %d", v, status)
		}
		env, root, err := parseRootEnvelope(body)
		if err != nil {
			r.RootChain = append(r.RootChain, ChainStep{Version: v, Status: "FAIL: " + err.Error()})
			return r, err
		}
		// Verify against the prior root (the previous iteration's
		// `latest`). The prior root's Root.keyids must include the
		// keyid the rotation used to co-sign.
		if err := verifySigsAgainstKeys(env, latest, "Root"); err != nil {
			r.RootChain = append(r.RootChain, ChainStep{
				Version: v, Signatures: len(env.Signatures),
				Status: "FAIL: prior-key verify: " + err.Error(),
			})
			return r, err
		}
		// And against the new root's own Root.keys (proves the new
		// key is willing to sign).
		if err := verifySigsAgainstKeys(env, root, "Root"); err != nil {
			r.RootChain = append(r.RootChain, ChainStep{
				Version: v, Signatures: len(env.Signatures),
				Status: "FAIL: new-key verify: " + err.Error(),
			})
			return r, err
		}
		r.RootChain = append(r.RootChain, ChainStep{
			Version: v, KeyID: rootKeyID(root), Signatures: len(env.Signatures),
			Status: "ok",
		})
		latest = root
	}
	r.LatestRoot = latest.Version
	currentRoot := latest

	// 3. Timestamp.
	tsBytes, err := fetchRole(cli, server, repo, "timestamp.json")
	if err != nil {
		return r, fmt.Errorf("fetch timestamp.json: %w", err)
	}
	tsEnv, tsPayload, err := parseTimestampEnvelope(tsBytes)
	if err != nil {
		return r, fmt.Errorf("parse timestamp: %w", err)
	}
	if err := verifySigsAgainstKeys(tsEnv, currentRoot, "Timestamp"); err != nil {
		r.Timestamp.Status = "FAIL: " + err.Error()
		return r, err
	}
	r.Timestamp = RoleVerification{Version: tsPayload.Version, Status: "ok"}

	// 4. Snapshot.
	snapBytes, err := fetchRole(cli, server, repo, "snapshot.json")
	if err != nil {
		return r, fmt.Errorf("fetch snapshot.json: %w", err)
	}
	snapEnv, snapPayload, err := parseSnapshotEnvelope(snapBytes)
	if err != nil {
		return r, fmt.Errorf("parse snapshot: %w", err)
	}
	if err := verifySigsAgainstKeys(snapEnv, currentRoot, "Snapshot"); err != nil {
		r.Snapshot.Status = "FAIL: " + err.Error()
		return r, err
	}
	// Cross-check: timestamp.meta.snapshot.json.{hashes.sha256, length}
	// must match the bytes we just fetched.
	if want, got := tsPayload.SnapshotHash(), sha256Hex(snapBytes); want != "" && want != got {
		r.Snapshot.Status = fmt.Sprintf("FAIL: hash mismatch (timestamp says %s, got %s)", want, got)
		return r, fmt.Errorf("snapshot hash mismatch")
	}
	if want := tsPayload.SnapshotLength(); want > 0 && want != int64(len(snapBytes)) {
		r.Snapshot.Status = fmt.Sprintf("FAIL: length mismatch (timestamp says %d, got %d)", want, len(snapBytes))
		return r, fmt.Errorf("snapshot length mismatch")
	}
	r.Snapshot = RoleVerification{Version: snapPayload.Version, Status: "ok"}

	// 5. Targets.
	tgtBytes, err := fetchRole(cli, server, repo, "targets.json")
	if err != nil {
		return r, fmt.Errorf("fetch targets.json: %w", err)
	}
	tgtEnv, tgtPayload, err := parseTargetsEnvelope(tgtBytes)
	if err != nil {
		return r, fmt.Errorf("parse targets: %w", err)
	}
	if err := verifySigsAgainstKeys(tgtEnv, currentRoot, "Targets"); err != nil {
		r.Targets.Status = "FAIL: " + err.Error()
		return r, err
	}
	// Cross-check: snapshot.meta.targets.json.version must match.
	if want := snapPayload.TargetsVersion(); want > 0 && want != tgtPayload.Version {
		r.Targets.Status = fmt.Sprintf("FAIL: targets.version=%d but snapshot.meta.targets.version=%d",
			tgtPayload.Version, want)
		return r, fmt.Errorf("targets version mismatch")
	}
	r.Targets = RoleVerification{Version: tgtPayload.Version, Status: "ok"}
	r.TargetCount = len(tgtPayload.Targets)
	return r, nil
}

// --- TUF metadata types (subset that we verify against) ---

type signed struct {
	Signatures []signature     `json:"signatures"`
	Signed     json.RawMessage `json:"signed"`
}

type signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type root struct {
	Type    string           `json:"_type"`
	Version int              `json:"version"`
	Keys    map[string]keyEntry `json:"keys"`
	Roles   map[string]roleEntry `json:"roles"`
}

type keyEntry struct {
	KeyType string             `json:"keytype"`
	Scheme  string             `json:"scheme"`
	KeyVal  struct {
		Public string `json:"public"`
	} `json:"keyval"`
}

type roleEntry struct {
	KeyIDs    []string `json:"keyids"`
	Threshold int      `json:"threshold"`
}

type timestampPayload struct {
	Version int                          `json:"version"`
	Meta    map[string]timestampMetaItem `json:"meta"`
}

type timestampMetaItem struct {
	Hashes map[string]string `json:"hashes"`
	Length int64             `json:"length"`
	Version int              `json:"version"`
}

func (t timestampPayload) SnapshotHash() string {
	if m, ok := t.Meta["snapshot.json"]; ok {
		return m.Hashes["sha256"]
	}
	return ""
}

func (t timestampPayload) SnapshotLength() int64 {
	if m, ok := t.Meta["snapshot.json"]; ok {
		return m.Length
	}
	return 0
}

type snapshotPayload struct {
	Version int                          `json:"version"`
	Meta    map[string]snapshotMetaItem `json:"meta"`
}

type snapshotMetaItem struct {
	Version int `json:"version"`
}

func (s snapshotPayload) TargetsVersion() int {
	if m, ok := s.Meta["targets.json"]; ok {
		return m.Version
	}
	return 0
}

type targetsPayload struct {
	Version int                       `json:"version"`
	Targets map[string]json.RawMessage `json:"targets"`
}

// --- HTTP fetch helpers ---

func fetchRoot(cli *http.Client, server, repo string, version int) ([]byte, int, error) {
	url := fmt.Sprintf("%s/api/v1/user_repo/%s/%d.root.json", server, repo, version)
	resp, err := cli.Get(url)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return body, resp.StatusCode, nil
}

func fetchRole(cli *http.Client, server, repo, name string) ([]byte, error) {
	url := fmt.Sprintf("%s/api/v1/user_repo/%s/%s", server, repo, name)
	resp, err := cli.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// --- envelope parsing ---

func parseRootEnvelope(body []byte) (*signed, *root, error) {
	var env signed
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, nil, err
	}
	var r root
	if err := json.Unmarshal(env.Signed, &r); err != nil {
		return nil, nil, err
	}
	return &env, &r, nil
}

func parseTimestampEnvelope(body []byte) (*signed, *timestampPayload, error) {
	var env signed
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, nil, err
	}
	var p timestampPayload
	if err := json.Unmarshal(env.Signed, &p); err != nil {
		return nil, nil, err
	}
	return &env, &p, nil
}

func parseSnapshotEnvelope(body []byte) (*signed, *snapshotPayload, error) {
	var env signed
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, nil, err
	}
	var p snapshotPayload
	if err := json.Unmarshal(env.Signed, &p); err != nil {
		return nil, nil, err
	}
	return &env, &p, nil
}

func parseTargetsEnvelope(body []byte) (*signed, *targetsPayload, error) {
	var env signed
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, nil, err
	}
	var p targetsPayload
	if err := json.Unmarshal(env.Signed, &p); err != nil {
		return nil, nil, err
	}
	return &env, &p, nil
}

func rootKeyID(r *root) string {
	if r == nil {
		return ""
	}
	if role, ok := r.Roles["Root"]; ok && len(role.KeyIDs) > 0 {
		return role.KeyIDs[0]
	}
	return ""
}

// --- signature verification ---

// verifyRoleSigs verifies the envelope's signatures against the role's
// own keys map (used for v1 self-verify only).
func verifyRoleSigs(env *signed, r *root, roleName string) error {
	return verifySigsAgainstKeys(env, r, roleName)
}

// verifySigsAgainstKeys verifies envelope signatures whose keyid is in
// the named role's keyids list, against the corresponding pubkey in
// r.Keys. Returns nil if at least `threshold` sigs verify.
func verifySigsAgainstKeys(env *signed, r *root, roleName string) error {
	role, ok := r.Roles[roleName]
	if !ok {
		return fmt.Errorf("role %s not present in root.roles", roleName)
	}
	allowed := make(map[string]bool, len(role.KeyIDs))
	for _, k := range role.KeyIDs {
		allowed[k] = true
	}
	canon, err := canonicalJSON(env.Signed)
	if err != nil {
		return fmt.Errorf("canonicalize signed payload: %w", err)
	}
	ok2 := 0
	for _, sig := range env.Signatures {
		if !allowed[sig.KeyID] {
			continue
		}
		keyEntry, ok := r.Keys[sig.KeyID]
		if !ok {
			continue
		}
		pub, err := parsePEMPublicKey(keyEntry.KeyVal.Public)
		if err != nil {
			return fmt.Errorf("parse pubkey %s: %w", sig.KeyID, err)
		}
		raw, err := hex.DecodeString(sig.Sig)
		if err != nil {
			return fmt.Errorf("hex-decode sig: %w", err)
		}
		if err := verifyBytes(pub, canon, raw, keyEntry.Scheme); err != nil {
			return fmt.Errorf("sig %s verify: %w", sig.KeyID, err)
		}
		ok2++
	}
	threshold := role.Threshold
	if threshold < 1 {
		threshold = 1
	}
	if ok2 < threshold {
		return fmt.Errorf("only %d/%d required sigs verified for role %s", ok2, threshold, roleName)
	}
	return nil
}

func verifyBytes(pub crypto.PublicKey, canon, sig []byte, scheme string) error {
	switch p := pub.(type) {
	case ed25519.PublicKey:
		if !ed25519.Verify(p, canon, sig) {
			return errors.New("ed25519 verify failed")
		}
		return nil
	case *rsa.PublicKey:
		digest := sha256.Sum256(canon)
		return rsa.VerifyPSS(p, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{
			SaltLength: 32, Hash: crypto.SHA256,
		})
	default:
		return fmt.Errorf("unsupported pubkey type %T (scheme=%s)", pub, scheme)
	}
}

func parsePEMPublicKey(pemStr string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// canonicalJSON reproduces the canonical-JSON encoding tufd uses
// when signing. Round-trips via Go's encoding/json to get a generic
// value, then re-emits with sorted keys + no whitespace + integer
// numbers. Must byte-match what the server signs or verification
// fails; we test against tufd's own canonicalJSON in publisher tests.
func canonicalJSON(in []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(in, &v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := canonEncode(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func canonEncode(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if x {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		canonString(buf, x)
	case float64:
		if x == float64(int64(x)) {
			buf.WriteString(strconv.FormatInt(int64(x), 10))
		} else {
			return fmt.Errorf("non-integer number in canonical JSON: %v", x)
		}
	case []any:
		buf.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonEncode(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			canonString(buf, k)
			buf.WriteByte(':')
			if err := canonEncode(buf, x[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unsupported type %T", v)
	}
	return nil
}

func canonString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
