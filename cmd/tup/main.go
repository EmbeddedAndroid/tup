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
  factory create <name>         Create a new factory
  factory list                  List all factories
  factory show <repo-id>        Show the signed root role for a factory
  version                       Print version
  help                          Show this help

Global flags:
  -url <URL>                    tufd base URL (default $TUP_URL or http://localhost:9001)
  -json                         JSON output (for agents and scripts)
  -timeout <duration>           Request timeout (default 30s)

Examples:
  tup factory create acme
  tup -json factory list
  tup -url https://tufd.internal:9001 factory show 0d9eaef2-1234-...
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
	case "factory":
		runFactory(ctx, client, args[1:], out)
	default:
		fail(fmt.Errorf("unknown command: %s", args[0]))
	}
}

func runFactory(ctx context.Context, c *api.Client, args []string, out output) {
	if len(args) == 0 {
		fail(fmt.Errorf("factory needs a subcommand: create | list | show"))
	}
	switch args[0] {
	case "create":
		if len(args) < 2 {
			fail(fmt.Errorf("factory create needs a name"))
		}
		resp, err := c.CreateNamespace(ctx, api.CreateRequest{Name: args[1]})
		if err != nil {
			fail(err)
		}
		out.factoryCreated(resp)
	case "list":
		facts, err := c.ListNamespaces(ctx)
		if err != nil {
			fail(err)
		}
		out.factories(facts)
	case "show":
		if len(args) < 2 {
			fail(fmt.Errorf("factory show needs a repo-id"))
		}
		body, checksum, err := c.FetchRoot(ctx, args[1])
		if err != nil {
			fail(err)
		}
		out.factoryRoot(args[1], checksum, body)
	default:
		fail(fmt.Errorf("unknown factory subcommand: %s", args[0]))
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

func (o output) factories(fs []api.Factory) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(fs)
		return
	}
	if len(fs) == 0 {
		fmt.Println("(no factories)")
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

func (o output) factoryCreated(r *api.CreateResponse) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(r)
		return
	}
	fmt.Printf("created factory %q\n", r.Name)
	fmt.Printf("  repo_id:      %s\n", r.RepoID)
	fmt.Printf("  root_keyid:   %s\n", r.RootKeyID)
	fmt.Printf("  root_version: %d\n", r.RootVersion)
}

func (o output) factoryRoot(repoID, checksum string, body []byte) {
	if o.json {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"repo_id":  repoID,
			"checksum": checksum,
			"root":     json.RawMessage(body),
		})
		return
	}
	fmt.Printf("factory %s\n  root checksum: %s\n  root size:     %d bytes\n\n",
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
