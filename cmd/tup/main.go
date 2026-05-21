package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
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
  namespace create <name>               Create a new namespace
  namespace list                        List all namespaces
  namespace show <repo-id>              Show the signed root role for a namespace
  publish <repo-id> <name> <version>    Publish a new target into a namespace
  version                               Print version
  help                                  Show this help

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
		fail(fmt.Errorf("namespace needs a subcommand: create | list | show"))
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
	default:
		fail(fmt.Errorf("unknown namespace subcommand: %s", args[0]))
	}
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
