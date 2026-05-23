package main

import (
	"archive/tar"
	"compress/gzip"
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
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/EmbeddedAndroid/tup/internal/api"
	"github.com/EmbeddedAndroid/tup/internal/backup"
	"github.com/EmbeddedAndroid/tup/internal/tufvalidate"
)

var Version = "dev"

const help = `tup — Foundries.io on-prem OTA stack CLI

Usage:
  tup [flags] <command> [args...]

Commands:
  project create <name>                         Create a new project
  project list                                  List all projects
  project show <project-id>                     Show the signed root role for a project
  project rotate <project-id>                   Rotate the root key (server-side dual-key)
  project validate <project-id>                 Walk the TUF chain end-to-end + verify all signatures
  project create-with-key --name <n> --root-pubkey <file>
                                                Bootstrap with a customer-held offline root key (cold-key)
  project finalize-create --staging-id <id> --signed <file>
                                                POST signed envelope to finalize cold-key bootstrap
  project stage-rotation <project-id> --new-pubkey <file>
                                                Start an offline rotation; downloads bytes-to-sign
  sign-rotation --tosign <file> --old-key <pem> --new-key <pem> -o <file>
                                                Locally sign a staged rotation envelope (2 keys)
  sign-bootstrap --tosign <file> --key <pem> -o <file>
                                                Locally sign a staged bootstrap envelope (1 key)
  project finalize-rotation <project-id> --signed <file>
                                                POST a customer-signed envelope to commit the rotation
  publish <project-id> <name> <version>         Publish a new target into a project
  unpublish <project-id> <name> <version>       Remove a target (bumps targets/snapshot/timestamp)
  version                                       Print version
  help                                          Show this help

  (`+"`project`"+` was previously named `+"`namespace`"+`; the old name still works.)

Global flags:
  -url <URL>                    tufd base URL (default $TUP_URL or http://localhost:9001)
  -json                         JSON output (for agents and scripts)
  -timeout <duration>           Request timeout (default 30s)

publish flags:
  -sha256 <hex>                 sha256 of the target artifact (required;
                                for OSTREE this is the commit hash)
  -ostree-commit <hex>          alias for -sha256; also forces -format OSTREE
                                and -length 0
  -ostree-repo <path>           resolve the commit from a local OSTree repo
                                via 'ostree rev-parse'; sets -sha256
                                automatically. Pair with -ostree-ref.
  -ostree-ref <ref>             OSTree ref to resolve (default "main")
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
  tup project create acme
  tup -json project list
  tup -url https://tufd.internal:9001 project show 0d9eaef2-1234-...
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
	case "project", "namespace":
		// `namespace` kept as a backward-compat alias for one release.
		runNamespace(ctx, client, args[1:], out)
	case "publish":
		runPublish(ctx, client, args[1:], out)
	case "ostree":
		runOstreeSubcommand(ctx, client, args[1:], out)
	case "unpublish":
		runUnpublish(ctx, client, args[1:], out)
	case "sign-rotation":
		// Top-level (not under `namespace`) because the operation is
		// offline + local — it doesn't talk to tufd. The customer
		// might run it on an air-gapped HSM host where -url isn't
		// even meaningful.
		runSignRotation(args[1:])
	case "sign-bootstrap":
		// Single-key variant of sign-rotation for the cold-key
		// bootstrap flow (only the new root key signs v=1; there's
		// no prior root to co-sign with).
		runSignBootstrap(args[1:])
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
	ostreeRepo := fs.String("ostree-repo", "", "path to an OSTree repo to resolve the commit from")
	ostreeRef := fs.String("ostree-ref", "main", "OSTree ref to resolve (used with -ostree-repo)")
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
	// -ostree-repo: derive the commit from a local OSTree repo via
	// `ostree rev-parse <ref>`. Takes precedence over -sha256 /
	// -ostree-commit if they're also set (the repo is the source of
	// truth in real CI flows).
	if *ostreeRepo != "" {
		commit, err := ostreeRevParse(*ostreeRepo, *ostreeRef)
		if err != nil {
			fail(fmt.Errorf("publish: resolve ostree commit from %s ref %s: %w",
				*ostreeRepo, *ostreeRef, err))
		}
		req.SHA256 = commit
		req.TargetFormat = "OSTREE"
		req.Length = 0
	} else if *ostreeCommit != "" {
		// -ostree-commit is the OSTREE shorthand; forces format+length.
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

// ostreeRevParse shells to `ostree rev-parse <ref> --repo=<path>` and
// returns the bare commit hash. Var so tests can override.
var ostreeRevParse = func(repoPath, ref string) (string, error) {
	cmd := exec.Command("ostree", "rev-parse", "--repo="+repoPath, ref)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ostree rev-parse: %w (out: %s)", err, strings.TrimSpace(string(out)))
	}
	hash := strings.TrimSpace(string(out))
	// Sanity: ostree commits are 64-char lowercase hex sha256.
	if len(hash) != 64 {
		return "", fmt.Errorf("ostree rev-parse returned unexpected output %q (want 64-hex commit)", hash)
	}
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", fmt.Errorf("ostree rev-parse returned non-hex output %q", hash)
		}
	}
	return hash, nil
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

// runUnpublish: DELETE /api/v1/user_repo/<rid>/targets/<name>-<version>
func runUnpublish(ctx context.Context, c *api.Client, args []string, out output) {
	if len(args) < 3 {
		fail(fmt.Errorf("unpublish needs: <repo-id> <name> <version>"))
	}
	repoID, name, version := args[0], args[1], args[2]
	key := name + "-" + version
	resp, err := c.UnpublishTarget(ctx, repoID, key)
	if err != nil {
		fail(err)
	}
	out.unpublishResult(key, resp)
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
		fail(fmt.Errorf("project needs a subcommand: create | list | show | rotate"))
	}
	switch args[0] {
	case "create":
		if len(args) < 2 {
			fail(fmt.Errorf("project create needs a name"))
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
			fail(fmt.Errorf("project show needs a project-id"))
		}
		body, checksum, err := c.FetchRoot(ctx, args[1])
		if err != nil {
			fail(err)
		}
		out.namespaceRoot(args[1], checksum, body)
	case "rotate":
		runNamespaceRotate(ctx, c, args[1:], out)
	case "validate":
		runNamespaceValidate(args[1:], out, c)
	case "stage-rotation":
		runStageRotation(ctx, c, args[1:], out)
	case "finalize-rotation":
		runFinalizeRotation(ctx, c, args[1:], out)
	case "create-with-key":
		runCreateWithKey(ctx, c, args[1:], out)
	case "finalize-create":
		runFinalizeCreate(ctx, c, args[1:], out)
	case "register-device":
		runRegisterDevice(ctx, c, args[1:], out)
	case "get-ca":
		runGetCA(ctx, c, args[1:], out)
	case "export-offline-keys":
		runExportOfflineKeys(ctx, c, args[1:], out)
	case "backup":
		runBackup(ctx, c, args[1:], out)
	case "restore":
		runRestore(args[1:], out)
	case "pin-device":
		runPinDevice(ctx, c, args[1:], out)
	case "unpin-device":
		runUnpinDevice(ctx, c, args[1:], out)
	case "list-pins":
		runListPins(ctx, c, args[1:], out)
	case "config":
		runConfigSubcommand(ctx, c, args[1:], out)
	case "app":
		runAppSubcommand(ctx, c, args[1:], out)
	case "wave":
		runWaveSubcommand(ctx, c, args[1:], out)
	case "import-build":
		runImportBuild(ctx, c, args[1:], out)
	default:
		fail(fmt.Errorf("unknown project subcommand: %s", args[0]))
	}
}

// runOstreeSubcommand dispatches `tup ostree <push>`. The push command
// is the first-class "upload a Yocto build" path: walks a local
// ostree archive repo and POSTs every object + PUTs every ref.
func runOstreeSubcommand(ctx context.Context, c *api.Client, args []string, out output) {
	if len(args) == 0 {
		fail(fmt.Errorf("ostree needs a subcommand: push"))
	}
	switch args[0] {
	case "push":
		runOstreePush(ctx, c, args[1:], out)
	case "gen-delta":
		runOstreeGenDelta(ctx, c, args[1:], out)
	case "list-deltas":
		runOstreeListDeltas(ctx, c, args[1:], out)
	default:
		fail(fmt.Errorf("unknown ostree subcommand: %s", args[0]))
	}
}

func runOstreeGenDelta(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("ostree-gen-delta", flag.ExitOnError)
	from := fs.String("from", "", "source commit sha (required)")
	to := fs.String("to", "", "target commit sha (required)")
	token := fs.String("admin-token", "", "TUFD_ADMIN_TOKEN (required)")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if len(fs.Args()) < 1 || *from == "" || *to == "" || *token == "" {
		fail(fmt.Errorf("ostree gen-delta <repo-id> --from <sha> --to <sha> --admin-token <T>"))
	}
	rid := fs.Args()[0]
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/api/v1/user_repo/"+rid+"/ostree/deltas?from="+*from+"&to="+*to, nil)
	req.Header.Set("OSF-TOKEN", *token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		fail(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fail(fmt.Errorf("status=%d body=%s", resp.StatusCode, body))
	}
	fmt.Printf("delta generated: %s\n", body)
}

func runOstreeListDeltas(ctx context.Context, c *api.Client, args []string, out output) {
	if len(args) < 1 {
		fail(fmt.Errorf("ostree list-deltas <repo-id>"))
	}
	rid := args[0]
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		c.BaseURL+"/api/v1/user_repo/"+rid+"/ostree/deltas", nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		fail(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}

func runOstreePush(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("ostree-push", flag.ExitOnError)
	from := fs.String("from", "", "local ostree archive repo path (required)")
	branch := fs.String("branch", "", "single branch to push (empty = all refs under refs/heads/)")
	token := fs.String("admin-token", "", "TUFD_ADMIN_TOKEN value for OSF-TOKEN header (required)")
	conc := fs.Int("c", 32, "concurrent uploads")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if len(fs.Args()) < 1 || *from == "" || *token == "" {
		fail(fmt.Errorf("ostree push <repo-id> --from <local-repo> --admin-token <T> [--branch X] [-c N]"))
	}
	repoID := fs.Args()[0]

	start := time.Now()
	stats, err := c.OstreePushRepo(ctx, repoID, *token, *from, *branch, *conc, func(s api.OstreePushStats) {
		if (s.Uploaded+s.Skipped)%200 == 0 {
			fmt.Fprintf(os.Stderr, "  progress: %d/%d (uploaded=%d skipped=%d errors=%d)\r",
				s.Uploaded+s.Skipped, s.Total, s.Uploaded, s.Skipped, s.Errors)
		}
	})
	dt := time.Since(start)
	if err != nil {
		fail(fmt.Errorf("after %s, %d/%d done: %w",
			dt.Truncate(time.Millisecond), stats.Uploaded+stats.Skipped, stats.Total, err))
	}
	mb := float64(stats.Bytes) / 1024 / 1024
	fmt.Fprintf(os.Stderr, "\nostree push %s done in %s:\n", repoID, dt.Truncate(time.Millisecond))
	fmt.Fprintf(os.Stderr, "  %d objects (uploaded %d / skipped %d / errors %d, %.1f MB)\n",
		stats.Total, stats.Uploaded, stats.Skipped, stats.Errors, mb)
}

// runImportBuild orchestrates pushing a complete build (ostree repo +
// compose-app bundles) from a local directory into a namespace. Same
// shape as a Foundries `fioctl targets offline-update` bundle:
//
//   <bundle>/
//     ostree_repo/         (archive repo)
//     apps/<name>/<ver>/   (optional compose-app bundles)
//
// Resulting target metadata still needs `tup publish` to register the
// commit as a Target (we don't auto-publish because the operator
// usually picks the version + tags + hardware id).
func runImportBuild(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("import-build", flag.ExitOnError)
	from := fs.String("from", "", "bundle directory containing ostree_repo/ (required)")
	branch := fs.String("branch", "", "single ostree branch to push (empty = all)")
	token := fs.String("admin-token", "", "TUFD_ADMIN_TOKEN for OSF-TOKEN (required)")
	conc := fs.Int("c", 32, "concurrent ostree object uploads")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if len(fs.Args()) < 1 || *from == "" || *token == "" {
		fail(fmt.Errorf("import-build <repo-id> --from <bundle> --admin-token <T> [--branch X] [-c N]"))
	}
	repoID := fs.Args()[0]

	ostreeDir := filepath.Join(*from, "ostree_repo")
	if st, err := os.Stat(ostreeDir); err != nil || !st.IsDir() {
		fail(fmt.Errorf("missing %s -- bundle must contain an ostree_repo/ subdir", ostreeDir))
	}
	fmt.Fprintf(os.Stderr, "▶ pushing ostree archive from %s\n", ostreeDir)
	start := time.Now()
	stats, err := c.OstreePushRepo(ctx, repoID, *token, ostreeDir, *branch, *conc, nil)
	if err != nil {
		fail(err)
	}
	fmt.Fprintf(os.Stderr, "  ostree: %d objects (uploaded %d / skipped %d, %.1f MB) in %s\n",
		stats.Total, stats.Uploaded, stats.Skipped, float64(stats.Bytes)/1024/1024,
		time.Since(start).Truncate(time.Millisecond))

	// Push compose-apps if the bundle has them.
	appsDir := filepath.Join(*from, "apps")
	if st, err := os.Stat(appsDir); err == nil && st.IsDir() {
		count := 0
		filepath.Walk(appsDir, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			// Layout: <bundle>/apps/<name>/<version>/<file>.tgz OR
			// just <bundle>/apps/<name>/<version>.tgz
			rel, _ := filepath.Rel(appsDir, p)
			parts := strings.Split(rel, "/")
			if len(parts) < 2 {
				return nil
			}
			name := parts[0]
			ver := strings.TrimSuffix(parts[1], ".tgz")
			f, err := os.Open(p)
			if err != nil {
				return nil
			}
			defer f.Close()
			if _, err := c.AppPush(ctx, repoID, name, ver, "import-build", f); err != nil {
				fmt.Fprintf(os.Stderr, "  app push failed %s:%s -- %v\n", name, ver, err)
				return nil
			}
			fmt.Fprintf(os.Stderr, "  pushed compose-app %s:%s\n", name, ver)
			count++
			return nil
		})
		fmt.Fprintf(os.Stderr, "  %d compose-app bundle(s) pushed\n", count)
	}
	fmt.Fprintf(os.Stderr, "\nnext: register the new commit as a Target with `tup publish %s <name> <ver> -ostree-commit <sha> ...`\n", repoID)
}

// runWaveSubcommand dispatches `tup namespace wave <create|list|delete|add|remove>`.
// Waves are per-device targets filtering on the image-repo path so
// aktualizr-lite (which never hits the director) honors per-device
// rollouts the same way aktualizr-primary already does via pins.
func runWaveSubcommand(ctx context.Context, c *api.Client, args []string, out output) {
	if len(args) == 0 {
		fail(fmt.Errorf("wave needs a subcommand: create | list | delete | add | remove"))
	}
	switch args[0] {
	case "create":
		runWaveCreate(ctx, c, args[1:], out)
	case "list":
		runWaveList(ctx, c, args[1:], out)
	case "delete":
		runWaveDelete(ctx, c, args[1:], out)
	case "add":
		runWaveAdd(ctx, c, args[1:], out)
	case "remove":
		runWaveRemove(ctx, c, args[1:], out)
	default:
		fail(fmt.Errorf("unknown wave subcommand: %s", args[0]))
	}
}

func runWaveCreate(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("wave-create", flag.ExitOnError)
	name := fs.String("name", "", "wave name (required)")
	tgts := fs.String("targets", "", "comma-separated target_keys")
	by := fs.String("by", "", "creator actor")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if len(fs.Args()) < 1 || *name == "" {
		fail(fmt.Errorf("wave create <repo-id> --name X [--targets k1,k2] [--by actor]"))
	}
	keys := []string{}
	if *tgts != "" {
		keys = strings.Split(*tgts, ",")
	}
	if err := c.WaveCreate(ctx, fs.Args()[0], *name, keys, *by); err != nil {
		fail(err)
	}
	fmt.Printf("wave %q created in %s with %d target(s)\n", *name, fs.Args()[0], len(keys))
}

func runWaveList(ctx context.Context, c *api.Client, args []string, out output) {
	if len(args) < 1 {
		fail(fmt.Errorf("wave list <repo-id>"))
	}
	waves, err := c.WaveList(ctx, args[0])
	if err != nil {
		fail(err)
	}
	out.waveListResult(args[0], waves)
}

func runWaveDelete(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("wave-delete", flag.ExitOnError)
	name := fs.String("name", "", "wave name (required)")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if len(fs.Args()) < 1 || *name == "" {
		fail(fmt.Errorf("wave delete <repo-id> --name X"))
	}
	if err := c.WaveDelete(ctx, fs.Args()[0], *name); err != nil {
		fail(err)
	}
	fmt.Printf("wave %q deleted\n", *name)
}

func runWaveAdd(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("wave-add", flag.ExitOnError)
	name := fs.String("name", "", "wave name (required)")
	device := fs.String("device-id", "", "device to add (required)")
	by := fs.String("by", "", "actor")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if len(fs.Args()) < 1 || *name == "" || *device == "" {
		fail(fmt.Errorf("wave add <repo-id> --name X --device-id D [--by actor]"))
	}
	if err := c.WaveAddMember(ctx, fs.Args()[0], *name, *device, *by); err != nil {
		fail(err)
	}
	fmt.Printf("added %s to wave %q\n", *device, *name)
}

func runWaveRemove(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("wave-remove", flag.ExitOnError)
	name := fs.String("name", "", "wave name (required)")
	device := fs.String("device-id", "", "device to remove (required)")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if len(fs.Args()) < 1 || *name == "" || *device == "" {
		fail(fmt.Errorf("wave remove <repo-id> --name X --device-id D"))
	}
	if err := c.WaveRemoveMember(ctx, fs.Args()[0], *name, *device); err != nil {
		fail(err)
	}
	fmt.Printf("removed %s from wave %q\n", *device, *name)
}

// runAppSubcommand dispatches `tup namespace app <push|list|rm>`.
// Wraps tufd's compose-app bundle store: operator uploads a tarball
// by (name, version); target publishes reference apps via the
// existing `-app <name>=<uri>` flag.
func runAppSubcommand(ctx context.Context, c *api.Client, args []string, out output) {
	if len(args) == 0 {
		fail(fmt.Errorf("app needs a subcommand: push | list | rm"))
	}
	switch args[0] {
	case "push":
		runAppPush(ctx, c, args[1:], out)
	case "list":
		runAppList(ctx, c, args[1:], out)
	case "rm":
		runAppRm(ctx, c, args[1:], out)
	default:
		fail(fmt.Errorf("unknown app subcommand: %s", args[0]))
	}
}

func runAppPush(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("app-push", flag.ExitOnError)
	name := fs.String("name", "", "compose-app name (required)")
	ver := fs.String("version", "", "compose-app version (required)")
	bundle := fs.String("from", "", "path to bundle tarball (default: stdin)")
	by := fs.String("by", "", "actor recording the upload")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if len(fs.Args()) < 1 || *name == "" || *ver == "" {
		fail(fmt.Errorf("app push <repo-id> --name X --version V [--from <tarball>] [--by <actor>]"))
	}
	repoID := fs.Args()[0]
	var r io.Reader = os.Stdin
	if *bundle != "" && *bundle != "-" {
		f, err := os.Open(*bundle)
		if err != nil {
			fail(err)
		}
		defer f.Close()
		r = f
	}
	app, err := c.AppPush(ctx, repoID, *name, *ver, *by, r)
	if err != nil {
		fail(err)
	}
	out.appPushResult(repoID, app)
}

func runAppList(ctx context.Context, c *api.Client, args []string, out output) {
	if len(args) < 1 {
		fail(fmt.Errorf("app list <repo-id>"))
	}
	apps, err := c.AppList(ctx, args[0])
	if err != nil {
		fail(err)
	}
	out.appListResult(args[0], apps)
}

func runAppRm(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("app-rm", flag.ExitOnError)
	name := fs.String("name", "", "compose-app name (required)")
	ver := fs.String("version", "", "compose-app version (required)")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if len(fs.Args()) < 1 || *name == "" || *ver == "" {
		fail(fmt.Errorf("app rm <repo-id> --name X --version V"))
	}
	if err := c.AppDelete(ctx, fs.Args()[0], *name, *ver); err != nil {
		fail(err)
	}
	fmt.Printf("removed app %s:%s\n", *name, *ver)
}

// runConfigSubcommand dispatches `tup namespace config <set|list|rm>`.
// Wraps tufd's fioconfig admin endpoints. Files stored plaintext on
// the server; encrypted per-device-pubkey at GET time by tufd.
func runConfigSubcommand(ctx context.Context, c *api.Client, args []string, out output) {
	if len(args) == 0 {
		fail(fmt.Errorf("config needs a subcommand: set | list | rm"))
	}
	switch args[0] {
	case "set":
		runConfigSet(ctx, c, args[1:], out)
	case "list":
		runConfigList(ctx, c, args[1:], out)
	case "rm":
		runConfigRm(ctx, c, args[1:], out)
	default:
		fail(fmt.Errorf("unknown config subcommand: %s", args[0]))
	}
}

func runConfigSet(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("config-set", flag.ExitOnError)
	name := fs.String("name", "", "file name on device (required)")
	path := fs.String("from", "", "read file content from this path (default: stdin)")
	unenc := fs.Bool("unencrypted", false, "store + serve plaintext (no per-device encryption)")
	on := fs.String("on-changed", "", "comma-separated on-changed handler paths")
	by := fs.String("by", "", "actor recording the upload")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if len(fs.Args()) < 1 || *name == "" {
		fail(fmt.Errorf("config set <repo-id> --name <file> [--from <path>] [--unencrypted] [--on-changed <cmd,...>] [--by <actor>]"))
	}
	repoID := fs.Args()[0]
	var content []byte
	var err error
	if *path == "" || *path == "-" {
		content, err = io.ReadAll(os.Stdin)
	} else {
		content, err = os.ReadFile(*path)
	}
	if err != nil {
		fail(err)
	}
	onChanged := []string{}
	if *on != "" {
		onChanged = strings.Split(*on, ",")
	}
	if err := c.ConfigSet(ctx, repoID, *name, content, *unenc, onChanged, *by); err != nil {
		fail(err)
	}
	out.configSetResult(repoID, *name, len(content), *unenc)
}

func runConfigList(ctx context.Context, c *api.Client, args []string, out output) {
	if len(args) < 1 {
		fail(fmt.Errorf("config list <repo-id>"))
	}
	files, err := c.ConfigList(ctx, args[0])
	if err != nil {
		fail(err)
	}
	out.configListResult(args[0], files)
}

func runConfigRm(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("config-rm", flag.ExitOnError)
	name := fs.String("name", "", "file name to remove (required)")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if len(fs.Args()) < 1 || *name == "" {
		fail(fmt.Errorf("config rm <repo-id> --name <file>"))
	}
	if err := c.ConfigDelete(ctx, fs.Args()[0], *name); err != nil {
		fail(err)
	}
	fmt.Printf("removed %s\n", *name)
}

// runPinDevice posts a pin to tufd. Repeated pins for the same
// (device, target) are no-ops on the server.
func runPinDevice(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("pin-device", flag.ExitOnError)
	devID := fs.String("device-id", "", "device-id to pin (required)")
	target := fs.String("target", "", "target key (e.g. lmp-2); required")
	by := fs.String("by", "", "actor recording the pin (optional)")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if len(fs.Args()) < 1 || *devID == "" || *target == "" {
		fail(fmt.Errorf("pin-device <repo-id> --device-id <id> --target <target-key> [--by <actor>]"))
	}
	repoID := fs.Args()[0]
	if err := c.PinDevice(ctx, repoID, *devID, *target, *by); err != nil {
		fail(err)
	}
	out.pinResult(repoID, *devID, *target)
}

func runUnpinDevice(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("unpin-device", flag.ExitOnError)
	devID := fs.String("device-id", "", "device-id to unpin (required)")
	target := fs.String("target", "", "remove only this target (default: remove all pins for device)")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if len(fs.Args()) < 1 || *devID == "" {
		fail(fmt.Errorf("unpin-device <repo-id> --device-id <id> [--target <target-key>]"))
	}
	repoID := fs.Args()[0]
	n, err := c.UnpinDevice(ctx, repoID, *devID, *target)
	if err != nil {
		fail(err)
	}
	out.unpinResult(repoID, *devID, *target, n)
}

func runListPins(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("list-pins", flag.ExitOnError)
	devID := fs.String("device-id", "", "restrict to this device (default: all pins in namespace)")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if len(fs.Args()) < 1 {
		fail(fmt.Errorf("list-pins <repo-id> [--device-id <id>]"))
	}
	repoID := fs.Args()[0]
	pins, err := c.ListPins(ctx, repoID, *devID)
	if err != nil {
		fail(err)
	}
	out.pinsList(repoID, *devID, pins)
}

// runBackup streams tufd's GET /api/v1/_backup tarball into --out.
// Whole-stack snapshot: keystore (encrypted .enc + .salt), all
// namespaces' tuf.db, all devca dirs. Operator MUST keep the
// keystore passphrase separately — without it the .enc files are
// useless on restore.
func runBackup(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	outPath := fs.String("out", "", "write tarball here (default: tufd-backup-<ts>.tgz)")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	r, suggested, err := c.Backup(ctx)
	if err != nil {
		fail(err)
	}
	defer r.Close()
	path := *outPath
	if path == "" {
		if suggested != "" {
			path = suggested
		} else {
			path = "tufd-backup.tgz"
		}
	}
	f, err := os.Create(path)
	if err != nil {
		fail(err)
	}
	defer f.Close()
	n, err := io.Copy(f, r)
	if err != nil {
		fail(err)
	}
	out.backupResult(path, n)
}

// runRestore extracts a backup tarball into a local data dir. LOCAL
// op — does NOT talk to tufd. Operator runs it against a stopped
// tufd's data dir, then starts tufd back up.
func runRestore(args []string, out output) {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "tufd data dir to restore into (REQUIRED — tufd must be stopped)")
	allowNonEmpty := fs.Bool("allow-non-empty", false, "allow restore into a non-empty dir (existing files overwritten)")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if len(fs.Args()) < 1 || *dataDir == "" {
		fail(fmt.Errorf("restore <tarball.tgz> --data-dir <path> [--allow-non-empty]"))
	}
	tarPath := fs.Args()[0]
	if !*allowNonEmpty {
		entries, _ := os.ReadDir(*dataDir)
		if len(entries) > 0 {
			fail(fmt.Errorf("data dir %s is non-empty; pass --allow-non-empty to overwrite", *dataDir))
		}
	}
	f, err := os.Open(tarPath)
	if err != nil {
		fail(err)
	}
	defer f.Close()
	if err := backup.Read(f, *dataDir); err != nil {
		fail(err)
	}
	out.restoreResult(tarPath, *dataDir)
}

// runRegisterDevice: POSTs to /api/v1/user_repo/<rid>/devices and
// writes cert.pem + key.pem + ca.pem into --out-dir for the operator
// to install on the device. Idempotent at the cert-issue level (each
// call mints a fresh keypair; the prior cert isn't revoked).
func runRegisterDevice(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("register-device", flag.ExitOnError)
	devID := fs.String("device-id", "", "device-id (becomes the cert CN, required)")
	outDir := fs.String("out-dir", ".", "directory to write cert.pem + key.pem + ca.pem")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if len(fs.Args()) < 1 || *devID == "" {
		fail(fmt.Errorf("register-device <repo-id> --device-id <id> [--out-dir <dir>]"))
	}
	repoID := fs.Args()[0]
	resp, err := c.RegisterDevice(ctx, repoID, *devID)
	if err != nil {
		fail(err)
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fail(err)
	}
	for name, content := range map[string]string{
		"cert.pem": resp.CertPEM,
		"key.pem":  resp.KeyPEM,
		"ca.pem":   resp.CAPEM,
	} {
		path := filepath.Join(*outDir, name)
		mode := os.FileMode(0o644)
		if name == "key.pem" {
			mode = 0o600
		}
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			fail(err)
		}
	}
	out.registerDeviceResult(resp, *outDir)
}

// runGetCA writes the namespace CA cert to --out (or stdout).
func runGetCA(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("get-ca", flag.ExitOnError)
	outPath := fs.String("out", "", "path to write ca.pem (empty = stdout)")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if len(fs.Args()) < 1 {
		fail(fmt.Errorf("get-ca <repo-id>"))
	}
	repoID := fs.Args()[0]
	pem, err := c.GetCA(ctx, repoID)
	if err != nil {
		fail(err)
	}
	if *outPath == "" {
		os.Stdout.Write(pem)
		return
	}
	if err := os.WriteFile(*outPath, pem, 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("wrote ca cert to %s (%d bytes)\n", *outPath, len(pem))
}

// runExportOfflineKeys writes a fioctl-compatible offline-creds.tgz
// containing the project's online targets role keypair, packed as
//
//	tufrepo/keys/fioctl-targets-<kid>.pub  AtsKey JSON (public only)
//	tufrepo/keys/fioctl-targets-<kid>.sec  AtsKey JSON (public + private)
//
// `fioctl waves init -k <this-file> ...` will then find our targets
// key in the tarball, sign the wave's targets metadata client-side,
// and POST to /ota/factories/{f}/waves/. On the server side our wave
// shim accepts the signed blob and seeds the wave from its target
// keys map.
//
// We export the targets key because it's the only key fioctl needs
// for `waves init` and `targets sign`. Root, snapshot, timestamp
// keys never leave tufd's keystore.
func runExportOfflineKeys(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("export-offline-keys", flag.ExitOnError)
	outPath := fs.String("out", "offline-creds.tgz", "tarball output path")
	role := fs.String("role", "targets", "role to export (targets only for now)")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if len(fs.Args()) < 1 {
		fail(fmt.Errorf("export-offline-keys <repo-id> [--out file.tgz] [--role targets]"))
	}
	repoID := fs.Args()[0]
	if *role != "targets" {
		fail(fmt.Errorf("only --role=targets is supported"))
	}
	key, err := c.ExportRoleKey(ctx, repoID, *role)
	if err != nil {
		fail(err)
	}
	if key.KeyType != "ed25519" {
		fail(fmt.Errorf("export-offline-keys: unsupported key type %q", key.KeyType))
	}
	// AtsKey shape fioctl expects.
	pubJSON, _ := json.Marshal(map[string]any{
		"keytype": key.KeyType,
		"keyval":  map[string]string{"public": key.Public},
	})
	secJSON, _ := json.Marshal(map[string]any{
		"keytype": key.KeyType,
		"keyval":  map[string]string{"public": key.Public, "private": key.Private},
	})
	base := fmt.Sprintf("tufrepo/keys/fioctl-%s-%s", *role, key.KID)
	files := []struct {
		name string
		data []byte
	}{
		{base + ".pub", pubJSON},
		{base + ".sec", secJSON},
	}

	f, err := os.Create(*outPath)
	if err != nil {
		fail(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, e := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name:    e.name,
			Mode:    0o600,
			Size:    int64(len(e.data)),
			ModTime: time.Now(),
		}); err != nil {
			fail(err)
		}
		if _, err := tw.Write(e.data); err != nil {
			fail(err)
		}
	}
	if err := tw.Close(); err != nil {
		fail(err)
	}
	if err := gz.Close(); err != nil {
		fail(err)
	}
	fmt.Printf("wrote offline-creds tarball: %s\n  role:    %s\n  keytype: %s\n  kid:     %s\n",
		*outPath, *role, key.KeyType, key.KID)
	fmt.Printf("Use with fioctl: fioctl waves init -k %s <wave-name> <version> <tag>\n", *outPath)
	_ = out
}

// runCreateWithKey: POST /api/v1/user_repo/_bootstrap-stage with the
// customer's pre-generated root pubkey. Writes tosign-<staging>.json
// for the offline signing step.
func runCreateWithKey(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("create-with-key", flag.ExitOnError)
	name := fs.String("name", "", "human-readable namespace label (required)")
	pubkey := fs.String("root-pubkey", "", "PEM SPKI file for the customer's offline root key (required)")
	outDir := fs.String("out-dir", ".", "directory to write tosign file into")
	keytype := fs.String("root-keytype", "ed25519", "ed25519 | rsa-4096")
	scheme := fs.String("root-scheme", "", "signature scheme (defaults to keytype's standard)")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if *name == "" || *pubkey == "" {
		fail(fmt.Errorf("create-with-key: --name and --root-pubkey are required"))
	}
	pubBytes, err := os.ReadFile(*pubkey)
	if err != nil {
		fail(fmt.Errorf("create-with-key: read pubkey: %w", err))
	}
	resp, err := c.BootstrapStage(ctx, api.BootstrapStageRequest{
		Name:             *name,
		RootPublicKeyPEM: string(pubBytes),
		RootKeyType:      *keytype,
		RootScheme:       *scheme,
	})
	if err != nil {
		fail(err)
	}
	tosignPath := filepath.Join(*outDir, "tosign-bootstrap-"+resp.StagingID+".json")
	if err := os.WriteFile(tosignPath, resp.BytesToSign, 0o644); err != nil {
		fail(fmt.Errorf("create-with-key: write tosign file: %w", err))
	}
	out.bootstrapStageResult(resp, tosignPath)
}

func runFinalizeCreate(ctx context.Context, c *api.Client, args []string, out output) {
	fs := flag.NewFlagSet("finalize-create", flag.ExitOnError)
	stagingID := fs.String("staging-id", "", "staging_id from `create-with-key` (required)")
	signed := fs.String("signed", "", "path to the signed envelope JSON (required)")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if *stagingID == "" || *signed == "" {
		fail(fmt.Errorf("finalize-create: --staging-id and --signed required"))
	}
	envBytes, err := os.ReadFile(*signed)
	if err != nil {
		fail(fmt.Errorf("finalize-create: read envelope: %w", err))
	}
	resp, err := c.BootstrapFinalize(ctx, api.BootstrapFinalizeRequest{
		StagingID: *stagingID,
		Envelope:  envBytes,
	})
	if err != nil {
		fail(err)
	}
	out.namespaceCreated(resp)
}

// runSignBootstrap: single-key variant of sign-rotation. The cold-key
// bootstrap envelope only needs the new root key's signature (there's
// no prior root to co-sign).
func runSignBootstrap(args []string) {
	fs := flag.NewFlagSet("sign-bootstrap", flag.ExitOnError)
	tosignPath := fs.String("tosign", "", "tosign file from `namespace create-with-key` (required)")
	keyPath := fs.String("key", "", "PEM PKCS#8 private key (required)")
	outPath := fs.String("o", "signed-bootstrap.json", "envelope output file")
	if err := fs.Parse(args); err != nil {
		fail(err)
	}
	if *tosignPath == "" || *keyPath == "" {
		fail(fmt.Errorf("sign-bootstrap: --tosign and --key required"))
	}
	tosign, err := os.ReadFile(*tosignPath)
	if err != nil {
		fail(fmt.Errorf("sign-bootstrap: read tosign: %w", err))
	}
	sig, err := signCanonicalWithPEM(tosign, *keyPath)
	if err != nil {
		fail(fmt.Errorf("sign-bootstrap: %w", err))
	}
	envelope := map[string]any{
		"signatures": []map[string]string{
			{"keyid": sig.KeyID, "sig": sig.Sig},
		},
		"signed": json.RawMessage(tosign),
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(*outPath, body, 0o600); err != nil {
		fail(fmt.Errorf("sign-bootstrap: write envelope: %w", err))
	}
	fmt.Printf("signed envelope written to %s\n", *outPath)
	fmt.Printf("  keyid: %s\n", sig.KeyID)
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

// runNamespaceValidate walks the TUF chain end-to-end against tufd and
// prints a per-role verification report. Uses internal/tufvalidate so
// the logic is exercise-able from Go tests too.
func runNamespaceValidate(args []string, out output, c *api.Client) {
	if len(args) == 0 {
		fail(fmt.Errorf("namespace validate needs a repo-id"))
	}
	repoID := args[0]
	r, err := tufvalidate.Validate(c.BaseURL, repoID)
	if r != nil {
		out.validateResult(r)
	}
	if err != nil {
		fail(err)
	}
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
		fmt.Printf("%-40s  %-20s  root v%d  key %s\n", f.ProjectID, f.Name, f.LatestRootVersion, key)
	}
}

func (o output) namespaceCreated(r *api.CreateResponse) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(r)
		return
	}
	fmt.Printf("created namespace %q\n", r.Name)
	fmt.Printf("  repo_id:      %s\n", r.ProjectID)
	fmt.Printf("  root_keyid:   %s\n", r.RootKeyID)
	fmt.Printf("  root_version: %d\n", r.RootVersion)
}

func (o output) bootstrapStageResult(r *api.BootstrapStageResponse, tosignPath string) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"staging_id":       r.StagingID,
			"project_id":          r.ProjectID,
			"name":             r.Name,
			"root_keyid":       r.RootKeyID,
			"targets_keyid":    r.TargetsKeyID,
			"snapshot_keyid":   r.SnapshotKeyID,
			"timestamp_keyid":  r.TimestampKeyID,
			"required_keyids":  r.RequiredKeyIDs,
			"expires_at":       r.ExpiresAt,
			"tosign_file":      tosignPath,
		})
		return
	}
	fmt.Printf("staged namespace bootstrap: %q\n", r.Name)
	fmt.Printf("  repo_id:           %s\n", r.ProjectID)
	fmt.Printf("  staging_id:        %s\n", r.StagingID)
	fmt.Printf("  expires:           %s\n", r.ExpiresAt)
	fmt.Printf("  root keyid:        %s  (offline; you sign with this)\n", r.RootKeyID)
	fmt.Printf("  targets keyid:     %s  (online, server-held)\n", r.TargetsKeyID)
	fmt.Printf("  snapshot keyid:    %s  (online, server-held)\n", r.SnapshotKeyID)
	fmt.Printf("  timestamp keyid:   %s  (online, server-held)\n", r.TimestampKeyID)
	fmt.Printf("  bytes to sign:     %s (%d bytes)\n", tosignPath, len(r.BytesToSign))
	fmt.Printf("\nNext:\n")
	fmt.Printf("  tup sign-bootstrap --tosign %s --key ROOT.pem -o signed.json\n", tosignPath)
	fmt.Printf("  tup namespace finalize-create --staging-id %s --signed signed.json\n", r.StagingID)
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

func (o output) validateResult(r *tufvalidate.Result) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(r)
		return
	}
	fmt.Printf("namespace %s — TUF chain validation\n", r.ProjectID)
	fmt.Printf("\nroot chain (latest: v%d)\n", r.LatestRoot)
	for _, step := range r.RootChain {
		marker := "  ✓"
		if step.Status != "ok" {
			marker = "  ✗"
		}
		fmt.Printf("%s v%-3d sigs=%d keyid=%s  %s\n",
			marker, step.Version, step.Signatures,
			truncKeyID(step.KeyID), step.Status)
	}
	fmt.Printf("\nrole verification (against latest root)\n")
	for _, rv := range []struct{ name string; v RoleVerification }{
		{"timestamp", roleConv(r.Timestamp)},
		{"snapshot ", roleConv(r.Snapshot)},
		{"targets  ", roleConv(r.Targets)},
	} {
		marker := "  ✓"
		if rv.v.Status != "ok" {
			marker = "  ✗"
		}
		fmt.Printf("%s %s v%-4d %s\n", marker, rv.name, rv.v.Version, rv.v.Status)
	}
	fmt.Printf("\ntargets in latest manifest: %d\n", r.TargetCount)
}

// RoleVerification is re-exported here so the format functions can
// reference it without re-importing tufvalidate (which is already in
// scope for the caller).
type RoleVerification = tufvalidate.RoleVerification

func roleConv(rv tufvalidate.RoleVerification) RoleVerification { return rv }

func truncKeyID(k string) string {
	if len(k) > 16 {
		return k[:8] + "…" + k[len(k)-4:]
	}
	return k
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

func (o output) registerDeviceResult(r *api.RegisterDeviceResponse, outDir string) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(r)
		return
	}
	fmt.Printf("registered device %q in namespace %s\n", r.DeviceID, r.ProjectID)
	fmt.Printf("  cert.pem   %s/cert.pem\n", outDir)
	fmt.Printf("  key.pem    %s/key.pem  (0600)\n", outDir)
	fmt.Printf("  ca.pem     %s/ca.pem\n", outDir)
	fmt.Println()
	fmt.Println("Install on the device:")
	fmt.Println("  scp cert.pem key.pem ca.pem fio@<device>:/var/sota/")
	fmt.Println("Then update /var/sota/sota.toml:")
	fmt.Println("  [tls]")
	fmt.Println("  client_certificate_path = \"/var/sota/cert.pem\"")
	fmt.Println("  pkey_path               = \"/var/sota/key.pem\"")
	fmt.Println("  ca_path                 = \"/var/sota/ca.pem\"")
}

func (o output) backupResult(path string, bytes int64) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"path": path, "bytes": bytes,
		})
		return
	}
	fmt.Printf("backup written to %s (%d bytes)\n", path, bytes)
	fmt.Println()
	fmt.Println("IMPORTANT: keep the tufd keystore passphrase separately.")
	fmt.Println("Without it the .enc files in the tarball are useless.")
}

func (o output) waveListResult(rid string, waves []api.Wave) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(waves)
		return
	}
	if len(waves) == 0 {
		fmt.Printf("no waves in %s\n", rid)
		return
	}
	fmt.Printf("%d wave(s) in %s:\n", len(waves), rid)
	for _, w := range waves {
		fmt.Printf("  %s\n", w.Name)
		if len(w.TargetKeys) > 0 {
			fmt.Printf("    targets: %s\n", strings.Join(w.TargetKeys, ", "))
		}
		if len(w.Members) > 0 {
			fmt.Printf("    members: %s\n", strings.Join(w.Members, ", "))
		}
	}
}

func (o output) appPushResult(rid string, app *api.App) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(app)
		return
	}
	fmt.Printf("pushed app %s:%s in %s (%d bytes, sha256 %s)\n",
		app.Name, app.Version, rid, app.Size, app.SHA256[:16])
	fmt.Println("reference from a target publish via:")
	fmt.Printf("  tup -url <tufd> publish %s <name> <ver> -ostree-commit ... \\\n", rid)
	fmt.Printf("    -hardware intel-corei7-64 -tags main \\\n")
	fmt.Printf("    -app %s=https://<gw>:9200/compose-apps/%s/%s\n",
		app.Name, app.Name, app.Version)
}

func (o output) appListResult(rid string, apps []api.App) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(apps)
		return
	}
	if len(apps) == 0 {
		fmt.Printf("no apps in %s\n", rid)
		return
	}
	fmt.Printf("%d app(s) in %s:\n", len(apps), rid)
	for _, a := range apps {
		fmt.Printf("  %-20s %-10s %s   %d bytes\n", a.Name, a.Version, a.SHA256[:16], a.Size)
	}
}

func (o output) configSetResult(rid, name string, size int, unenc bool) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"project_id": rid, "name": name, "size": size, "unencrypted": unenc,
		})
		return
	}
	enc := "encrypted per-device on fetch"
	if unenc {
		enc = "plaintext (operator opt-out)"
	}
	fmt.Printf("config set %q in %s (%d bytes, %s)\n", name, rid, size, enc)
}

func (o output) configListResult(rid string, files []api.ConfigFile) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(files)
		return
	}
	if len(files) == 0 {
		fmt.Printf("no config files in %s\n", rid)
		return
	}
	fmt.Printf("%d config file(s) in %s:\n", len(files), rid)
	for _, f := range files {
		mode := ""
		if f.Unencrypted {
			mode = " (unencrypted)"
		}
		fmt.Printf("  %-24s %d bytes%s\n", f.Name, len(f.Value), mode)
		if len(f.OnChanged) > 0 {
			fmt.Printf("    on-changed: %s\n", strings.Join(f.OnChanged, ", "))
		}
	}
}

func (o output) pinResult(rid, deviceID, target string) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{
			"project_id": rid, "device_id": deviceID, "target": target,
		})
		return
	}
	fmt.Printf("pinned %s -> %s in %s\n", deviceID, target, rid)
	fmt.Println("Device will see ONLY this target on its next director poll.")
}

func (o output) unpinResult(rid, deviceID, target string, removed int) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"project_id": rid, "device_id": deviceID, "target": target, "removed": removed,
		})
		return
	}
	if target == "" {
		fmt.Printf("unpinned %s in %s (%d row(s) removed)\n", deviceID, rid, removed)
	} else {
		fmt.Printf("unpinned %s -> %s in %s (%d row(s) removed)\n", deviceID, target, rid, removed)
	}
}

func (o output) pinsList(rid, deviceID string, pins []api.DevicePin) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"project_id": rid, "device_id": deviceID, "pins": pins,
		})
		return
	}
	if len(pins) == 0 {
		fmt.Printf("no pins in %s", rid)
		if deviceID != "" {
			fmt.Printf(" for device %s", deviceID)
		}
		fmt.Println()
		return
	}
	fmt.Printf("%d pin(s) in %s:\n", len(pins), rid)
	for _, p := range pins {
		fmt.Printf("  %s  ->  %s   (by %s)\n", p.DeviceID, p.TargetKey, p.PinnedBy)
	}
}

func (o output) restoreResult(tarPath, dataDir string) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{
			"tarball": tarPath, "data_dir": dataDir,
		})
		return
	}
	fmt.Printf("restored %s into %s\n", tarPath, dataDir)
	fmt.Println("Start tufd against this data dir with the original")
	fmt.Println("keystore passphrase (TUFD_KEYSTORE_PASSPHRASE).")
}

func (o output) unpublishResult(key string, r *api.PublishResponse) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(r)
		return
	}
	fmt.Printf("unpublished %s\n", key)
	fmt.Printf("  targets:   v%d\n", r.TargetsVersion)
	fmt.Printf("  snapshot:  v%d\n", r.SnapshotVersion)
	fmt.Printf("  timestamp: v%d\n", r.TimestampVersion)
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
			"project_id":  repoID,
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
