package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/foundriesio/tup/internal/api"
)

var Version = "dev"

const help = `tup — Foundries.io on-prem OTA stack CLI

Usage:
  tup [flags] <command> [args...]

Commands:
  namespace create <name>                       Create a new namespace
  namespace list                                List all namespaces
  namespace show <repo-id>                      Show the signed root role for a namespace
  namespace rotate <repo-id>                    Rotate the root key (server-side dual-key)
  namespace stage-rotation <repo-id> --new-pubkey <file>
                                                Start an offline rotation; downloads bytes-to-sign
  sign-rotation --tosign <file> --old-key <pem> --new-key <pem> -o <file>
                                                Locally sign a staged rotation envelope
  namespace finalize-rotation <repo-id> --signed <file>
                                                POST a customer-signed envelope to commit the rotation
  publish <repo-id> <name> <version>            Publish a new target into a namespace
  version                                       Print version
  help                                          Show this help

Global flags:
  -url <URL>                    tufd base URL (default $TUP_URL or http://localhost:9001)
  -json                         JSON output (for agents and scripts)
  -timeout <duration>           Request timeout (default 30s)

publish flags:
  -sha256 <hex>                 sha256 of the target artifact (required;
                                for OSTREE this is the commit hash)
  -ostree-commit <hex>          alias for -sha256; also forces -format OSTREE
                                and -length 0
  -length <int>                 byte length; 0 for OSTREE targets
  -hardware <h1,h2,...>         comma-separated hardware ids
  -tags <t1,t2,...>             comma-separated tag list
  -format <OSTREE|BINARY>       target format; default OSTREE
  -uri <url>                    artifact URI (devices fetch the artifact here)
  -orig-uri <url>               upstream build URL (e.g. Foundries CI)
  -image-file <name>            artifact filename (e.g. lmp-base-…wic.gz)
  -app <name=uri[,name=uri...]> docker-compose apps for this target
  -lmp-ver <n>                  LmP version label
  -lmp-manifest-sha <hex>       lmp-manifest git sha at build time
  -meta-sha <hex>               meta-subscriber-overrides git sha at build time
  -containers-sha <hex>         containers.git sha at build time
  -manifest <path>              load a build manifest (JSON) for any of the
                                above; explicit flags override

Examples:
  tup namespace create acme
  tup -json namespace list
  tup -url https://tufd.internal:9001 namespace show 0d9eaef2-1234-...
  tup publish demo lmp 42 -sha256 abc123... -hardware intel-corei7-64 -tags main
  tup publish demo lmp 98 -manifest build-98.json -hardware intel-corei7-64
`

func main() {
	url := flag.String("url", envOr("TUP_URL", "http://localhost:9001"), "tufd base URL")
	jsonOut := flag.Bool("json", false, "output JSON")
	timeout := flag.Duration("timeout", 30*time.Second, "request timeout")
	flag.Usage = func() { fmt.Fprint(os.Stderr, help) }
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, help)
		os.Exit(2)
	}

	client := api.New(*url)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	out := output{json: *jsonOut}

	switch args[0] {
	case "version":
		out.scalar("version", Version)
	case "help", "-h", "--help":
		fmt.Fprint(os.Stderr, help)
	case "namespace":
		runNamespace(ctx, client, args[1:], out)
	case "publish":
		runPublish(ctx, client, args[1:], out)
	case "sign-rotation":
		// Top-level (not under `namespace`) because the operation is
		// offline + local — it doesn't talk to tufd. The customer
		// might run it on an air-gapped HSM host where -url isn't
		// even meaningful.
		runSignRotation(args[1:])
	default:
		fail(fmt.Errorf("unknown command: %s", args[0]))
	}
}

func runPublish(ctx context.Context, c *api.Client, args []string, out output) {
	if len(args) < 3 {
		fail(fmt.Errorf("publish needs: <repo-id> <name> <version> [flags]"))
	}
	repoID, name, version := args[0], args[1], args[2]

	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	manifestPath := fs.String("manifest", "", "load a build manifest JSON (LmP fields)")
	sha256 := fs.String("sha256", "", "sha256 hex of the target artifact")
	ostreeCommit := fs.String("ostree-commit", "", "ostree commit hash (alias for -sha256, forces OSTREE format)")
	length := fs.Int64("length", 0, "byte length; 0 for OSTREE")
	hardware := fs.String("hardware", "", "comma-separated hardware ids")
	tags := fs.String("tags", "", "comma-separated tags")
	format := fs.String("format", "OSTREE", "OSTREE | BINARY")
	uri := fs.String("uri", "", "artifact URI")
	origURI := fs.String("orig-uri", "", "upstream build URL")
	imageFile := fs.String("image-file", "", "artifact filename")
	apps := fs.String("app", "", "compose apps name=uri[,name=uri...]")
	lmpVer := fs.String("lmp-ver", "", "LmP version label")
	lmpManifestSHA := fs.String("lmp-manifest-sha", "", "lmp-manifest git sha")
	metaSHA := fs.String("meta-sha", "", "meta-subscriber-overrides git sha")
	containersSHA := fs.String("containers-sha", "", "containers.git sha")
	if err := fs.Parse(args[3:]); err != nil {
		fail(err)
	}

	// Build the base request from the manifest (if any), then layer
	// explicit flags on top — flags always win.
	req := api.PublishRequest{Name: name, Version: version, TargetFormat: "OSTREE"}
	if *manifestPath != "" {
		loaded, err := loadManifest(*manifestPath)
		if err != nil {
			fail(fmt.Errorf("publish: load manifest: %w", err))
		}
		mergeManifest(&req, loaded)
	}
	// -ostree-commit is the OSTREE shorthand; forces format+length.
	if *ostreeCommit != "" {
		if *sha256 != "" && *sha256 != *ostreeCommit {
			fail(fmt.Errorf("publish: -sha256 and -ostree-commit disagree"))
		}
		req.SHA256 = *ostreeCommit
		req.TargetFormat = "OSTREE"
		req.Length = 0
	} else if *sha256 != "" {
		req.SHA256 = *sha256
	}
	// Each explicit flag wins over the manifest value when non-empty.
	if *length != 0 {
		req.Length = *length
	}
	if *format != "OSTREE" || req.TargetFormat == "" {
		req.TargetFormat = *format
	}
	if *hardware != "" {
		req.HardwareIDs = splitCSV(*hardware)
	}
	if *tags != "" {
		req.Tags = splitCSV(*tags)
	}
	if *uri != "" {
		req.URI = *uri
	}
	if *origURI != "" {
		req.OrigURI = *origURI
	}
	if *imageFile != "" {
		req.ImageFile = *imageFile
	}
	if *apps != "" {
		req.ComposeApps = parseAppPairs(*apps)
	}
	if *lmpVer != "" {
		req.LMPVer = *lmpVer
	}
	if *lmpManifestSHA != "" {
		req.LMPManifestSHA = *lmpManifestSHA
	}
	if *metaSHA != "" {
		req.MetaSubscriberOverridesSHA = *metaSHA
	}
	if *containersSHA != "" {
		req.ContainersSHA = *containersSHA
	}

	if req.SHA256 == "" {
		fail(fmt.Errorf("publish: -sha256 (or -ostree-commit, or manifest's sha256) is required"))
	}
	resp, err := c.PublishTarget(ctx, repoID, req)
	if err != nil {
		fail(err)
	}
	out.publishResult(resp)
}

// loadManifest reads a JSON build manifest into a PublishRequest. Any
// fields a real Foundries CI emits land here; unknown fields are ignored.
// Caller layers explicit CLI flags on top.
func loadManifest(path string) (*api.PublishRequest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m api.PublishRequest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// mergeManifest copies non-empty fields from src into dst. Used by publish
// to seed the request from a manifest before the per-flag overlay.
func mergeManifest(dst, src *api.PublishRequest) {
	if src.SHA256 != "" {
		dst.SHA256 = src.SHA256
	}
	if src.Length != 0 {
		dst.Length = src.Length
	}
	if src.TargetFormat != "" {
		dst.TargetFormat = src.TargetFormat
	}
	if len(src.HardwareIDs) > 0 {
		dst.HardwareIDs = src.HardwareIDs
	}
	if len(src.Tags) > 0 {
		dst.Tags = src.Tags
	}
	if src.URI != "" {
		dst.URI = src.URI
	}
	if src.OrigURI != "" {
		dst.OrigURI = src.OrigURI
	}
	if src.ImageFile != "" {
		dst.ImageFile = src.ImageFile
	}
	if len(src.ComposeApps) > 0 {
		dst.ComposeApps = src.ComposeApps
	}
	if src.LMPVer != "" {
		dst.LMPVer = src.LMPVer
	}
	if src.LMPManifestSHA != "" {
		dst.LMPManifestSHA = src.LMPManifestSHA
	}
	if src.MetaSubscriberOverridesSHA != "" {
		dst.MetaSubscriberOverridesSHA = src.MetaSubscriberOverridesSHA
	}
	if src.ContainersSHA != "" {
		dst.ContainersSHA = src.ContainersSHA
	}
}

// splitCSV splits a comma-separated list, dropping empty entries.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// parseAppPairs turns "web=ghcr.io/acme/web:1,db=ghcr.io/acme/db:2" into a
// {web: ghcr.io/.../web:1, db: ...} map.
func parseAppPairs(s string) map[string]string {
	if s == "" {
		return nil
	}
	out := make(map[string]string)
	for _, p := range strings.Split(s, ",") {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) == 2 && kv[0] != "" && kv[1] != "" {
			out[kv[0]] = kv[1]
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func runNamespace(ctx context.Context, c *api.Client, args []string, out output) {
	if len(args) == 0 {
		fail(fmt.Errorf("namespace needs a subcommand: create | list | show | rotate"))
	}
	switch args[0] {
	case "create":
		if len(args) < 2 {
			fail(fmt.Errorf("namespace create needs a name"))
		}
		resp, err := c.CreateNamespace(ctx, api.CreateRequest{Name: args[1]})
		if err != nil {
			fail(err)
		}
		out.namespaceCreated(resp)
	case "list":
		facts, err := c.ListNamespaces(ctx)
		if err != nil {
			fail(err)
		}
		out.namespaces(facts)
	case "show":
		if len(args) < 2 {
			fail(fmt.Errorf("namespace show needs a repo-id"))
		}
		body, checksum, err := c.FetchRoot(ctx, args[1])
		if err != nil {
			fail(err)
		}
		out.namespaceRoot(args[1], checksum, body)
	case "rotate":
		runNamespaceRotate(ctx, c, args[1:], out)
	case "stage-rotation":
		runStageRotation(ctx, c, args[1:], out)
	case "finalize-rotation":
		runFinalizeRotation(ctx, c, args[1:], out)
	default:
		fail(fmt.Errorf("unknown namespace subcommand: %s", args[0]))
	}
}

// runStageRotation: POST /root/stage with the customer's new pubkey.
// Writes the bytes-to-sign to a file the customer can hand to their
// offline signing setup, plus prints the staging_id needed at
// finalize time.
func runStageRotation(ctx context.Context, c *api.Client, args []string, out output) {
	if len(args) == 0 {
		fail(fmt.Errorf("stage-rotation needs a repo-id"))
	}
	repoID := args[0]
	fs := flag.NewFlagSet("stage-rotation", flag.ExitOnError)
	newPubkey := fs.String("new-pubkey", "", "PEM-encoded SPKI public key file (required)")
	outDir := fs.String("out-dir", ".", "directory to write the bytes-to-sign file into")
	keytype := fs.String("keytype", "ed25519", "ed25519 | rsa-4096")
	scheme := fs.String("scheme", "", "signature scheme (defaults to keytype's standard)")
	if err := fs.Parse(args[1:]); err != nil {
		fail(err)
	}
	if *newPubkey == "" {
		fail(fmt.Errorf("stage-rotation: --new-pubkey <file> is required"))
	}
	pubBytes, err := os.ReadFile(*newPubkey)
	if err != nil {
		fail(fmt.Errorf("stage-rotation: read pubkey: %w", err))
	}
	resp, err := c.StageRotation(ctx, repoID, api.StageRotationRequest{
		NewPublicKeyPEM: string(pubBytes),
		NewKeyType:      *keytype,
		NewScheme:       *scheme,
	})
	if err != nil {
		fail(err)
	}
	tosignPath := filepath.Join(*outDir, "tosign-"+resp.StagingID+".json")
	if err := os.WriteFile(tosignPath, resp.BytesToSign, 0o644); err != nil {
		fail(fmt.Errorf("stage-rotation: write tosign file: %w", err))
	}
	out.stageRotationResult(resp, tosignPath)
}

// runFinalizeRotation: POST /root/finalize with a customer-signed
// envelope file. The envelope file MUST be the {signatures, signed}
// JSON the offline signer produced (or what `sign-rotation` wrote).
func runFinalizeRotation(ctx context.Context, c *api.Client, args []string, out output) {
	if len(args) == 0 {
		fail(fmt.Errorf("finalize-rotation needs a repo-id"))
	}
	repoID := args[0]
	fs := flag.NewFlagSet("finalize-rotation", flag.ExitOnError)
	signed := fs.String("signed", "", "path to the signed envelope JSON (required)")
	stagingID := fs.String("staging-id", "", "staging_id from `stage-rotation` (required)")
	if err := fs.Parse(args[1:]); err != nil {
		fail(err)
	}
	if *signed == "" || *stagingID == "" {
		fail(fmt.Errorf("finalize-rotation: --signed <file> and --staging-id <id> required"))
	}
	envBytes, err := os.ReadFile(*signed)
	if err != nil {
		fail(fmt.Errorf("finalize-rotation: read envelope: %w", err))
	}
	resp, err := c.FinalizeRotation(ctx, repoID, api.FinalizeRotationRequest{
		StagingID: *stagingID,
		Envelope:  envBytes,
	})
	if err != nil {
		fail(err)
	}
	out.rotateResult(resp)
}

// runSignRotation reads a tosign file + two private key files (the
// old root key and the new root key the customer just minted), signs
// the tosign bytes with both, and writes the resulting envelope to
// -o. Supports ed25519 and RSA private keys in PEM PKCS#8 form (the
// shape `openssl genpkey -algorithm ed25519` produces).
func runSignRotation(args []string) {
	fs := flag.NewFlagSet("sign-rotation", flag.ExitOnError)
	tosignPath := fs.String("tosign", "", "tosign file from `stage-rotation` (required)")
	oldKeyPath := fs.String("old-key", "", "PEM PKCS#8 private key for the CURRENT root key (required)")
	newKeyPath := fs.String("new-key", "", "PEM PKCS#8 private key for the NEW root key (required)")
	outPath := fs.String("o", "signed-rotation.json", "envelope output file")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if *tosignPath == "" || *oldKeyPath == "" || *newKeyPath == "" {
		fail(fmt.Errorf("sign-rotation: --tosign, --old-key, --new-key all required"))
	}
	tosign, err := os.ReadFile(*tosignPath)
	if err != nil {
		fail(fmt.Errorf("sign-rotation: read tosign: %w", err))
	}
	oldSig, err := signCanonicalWithPEM(tosign, *oldKeyPath)
	if err != nil {
		fail(fmt.Errorf("sign-rotation: old key: %w", err))
	}
	newSig, err := signCanonicalWithPEM(tosign, *newKeyPath)
	if err != nil {
		fail(fmt.Errorf("sign-rotation: new key: %w", err))
	}
	envelope := map[string]any{
		"signatures": []map[string]string{
			{"keyid": oldSig.KeyID, "sig": oldSig.Sig},
			{"keyid": newSig.KeyID, "sig": newSig.Sig},
		},
		"signed": json.RawMessage(tosign),
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(*outPath, body, 0o600); err != nil {
		fail(fmt.Errorf("sign-rotation: write envelope: %w", err))
	}
	fmt.Printf("signed envelope written to %s\n", *outPath)
	fmt.Printf("  old keyid:  %s\n", oldSig.KeyID)
	fmt.Printf("  new keyid:  %s\n", newSig.KeyID)
}

// pemSignature is the {keyid, sig} pair the offline signer produces.
type pemSignature struct {
	KeyID string
	Sig   string
}

// signCanonicalWithPEM reads a PEM PKCS#8 private key, computes the
// matching keyid (sha256 of SPKI DER), and signs `canonical` with the
// appropriate algorithm. Supports ed25519 + RSA; matches the
// algorithms tufd's tuflib.SignBytes uses.
func signCanonicalWithPEM(canonical []byte, keyPath string) (*pemSignature, error) {
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", keyPath)
	}
	privAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8: %w", err)
	}

	// Derive the keyid from the SPKI DER of the matching public key.
	var pubKey crypto.PublicKey
	switch k := privAny.(type) {
	case ed25519.PrivateKey:
		pubKey = k.Public()
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	default:
		return nil, fmt.Errorf("unsupported private key type %T", privAny)
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}
	kidSum := sha256Sum(spkiDER)
	kid := hexEncode(kidSum[:])

	// Sign.
	var rawSig []byte
	switch k := privAny.(type) {
	case ed25519.PrivateKey:
		rawSig = ed25519.Sign(k, canonical)
	case *rsa.PrivateKey:
		digest := sha256Sum(canonical)
		rawSig, err = rsa.SignPSS(rand.Reader, k, crypto.SHA256, digest[:],
			&rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256})
		if err != nil {
			return nil, err
		}
	}
	return &pemSignature{KeyID: kid, Sig: hexEncode(rawSig)}, nil
}

func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

func hexEncode(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = hex[x>>4]
		out[i*2+1] = hex[x&0x0f]
	}
	return string(out)
}

func runNamespaceRotate(ctx context.Context, c *api.Client, args []string, out output) {
	if len(args) == 0 {
		fail(fmt.Errorf("namespace rotate needs a repo-id"))
	}
	repoID := args[0]

	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	keyType := fs.String("key-type", "", "key algorithm for the new root (default: same as current)")
	if err := fs.Parse(args[1:]); err != nil {
		fail(err)
	}
	resp, err := c.RotateRoot(ctx, repoID, api.RotateRootRequest{KeyType: *keyType})
	if err != nil {
		fail(err)
	}
	out.rotateResult(resp)
}

// output wraps text-vs-json formatting in one place.
type output struct{ json bool }

func (o output) scalar(key, val string) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{key: val})
		return
	}
	fmt.Println(val)
}

func (o output) namespaces(fs []api.Factory) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(fs)
		return
	}
	if len(fs) == 0 {
		fmt.Println("(no namespaces)")
		return
	}
	for _, f := range fs {
		key := f.RootKeyID
		if len(key) > 16 {
			key = key[:8] + "…" + key[len(key)-4:]
		}
		fmt.Printf("%-40s  %-20s  root v%d  key %s\n", f.RepoID, f.Name, f.LatestRootVersion, key)
	}
}

func (o output) namespaceCreated(r *api.CreateResponse) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(r)
		return
	}
	fmt.Printf("created namespace %q\n", r.Name)
	fmt.Printf("  repo_id:      %s\n", r.RepoID)
	fmt.Printf("  root_keyid:   %s\n", r.RootKeyID)
	fmt.Printf("  root_version: %d\n", r.RootVersion)
}

func (o output) stageRotationResult(r *api.StageRotationResponse, tosignPath string) {
	if o.json {
		out := map[string]any{
			"staging_id":       r.StagingID,
			"new_root_version": r.NewRootVersion,
			"new_root_keyid":   r.NewRootKeyID,
			"prior_root_keyid": r.PriorRootKeyID,
			"required_keyids":  r.RequiredKeyIDs,
			"expires_at":       r.ExpiresAt,
			"tosign_file":      tosignPath,
		}
		_ = json.NewEncoder(os.Stdout).Encode(out)
		return
	}
	fmt.Printf("staged rotation: v%d (prior keyid %s)\n",
		r.NewRootVersion, r.PriorRootKeyID)
	fmt.Printf("  new keyid:     %s\n", r.NewRootKeyID)
	fmt.Printf("  staging id:    %s\n", r.StagingID)
	fmt.Printf("  expires:       %s\n", r.ExpiresAt)
	fmt.Printf("  signers req:   %d keys must sign the new root\n", len(r.RequiredKeyIDs))
	for _, kid := range r.RequiredKeyIDs {
		fmt.Printf("    - %s\n", kid)
	}
	fmt.Printf("  bytes to sign: %s (%d bytes)\n", tosignPath, len(r.BytesToSign))
	fmt.Printf("\nNext:\n")
	fmt.Printf("  tup sign-rotation --tosign %s --old-key OLD.pem --new-key NEW.pem -o signed.json\n", tosignPath)
	fmt.Printf("  tup namespace finalize-rotation <rid> --staging-id %s --signed signed.json\n", r.StagingID)
}

func (o output) rotateResult(r *api.RotateRootResponse) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(r)
		return
	}
	fmt.Printf("rotated: v%d -> v%d\n", r.PriorRootVersion, r.NewRootVersion)
	fmt.Printf("  new keyid:   %s\n", r.NewRootKeyID)
	fmt.Printf("  prior keyid: %s\n", r.PriorRootKeyID)
}

func (o output) publishResult(r *api.PublishResponse) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(r)
		return
	}
	fmt.Printf("published %s\n", r.TargetKey)
	fmt.Printf("  targets:   v%d\n", r.TargetsVersion)
	fmt.Printf("  snapshot:  v%d\n", r.SnapshotVersion)
	fmt.Printf("  timestamp: v%d\n", r.TimestampVersion)
}

func (o output) namespaceRoot(repoID, checksum string, body []byte) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"repo_id":  repoID,
			"checksum": checksum,
			"root":     json.RawMessage(body),
		})
		return
	}
	fmt.Printf("namespace %s\n  root checksum: %s\n  root size:     %d bytes\n\n",
		repoID, checksum, len(body))
	fmt.Println(string(body))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "tup:", err)
	if strings.Contains(err.Error(), "status=4") {
		os.Exit(3) // client error
	}
	os.Exit(1)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
