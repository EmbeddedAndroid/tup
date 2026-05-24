package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestParseImageRef(t *testing.T) {
	cases := []struct {
		in      string
		host    string
		repo    string
		tag     string
		wantErr bool
	}{
		{"registry.example:5000/proj/app:1", "registry.example:5000", "proj/app", "1", false},
		{"192.168.1.5:5000/demo/hello-test:latest", "192.168.1.5:5000", "demo/hello-test", "latest", false},
		{"docker.io/library/alpine:3", "docker.io", "library/alpine", "3", false},
		{"alpine:3", "docker.io", "library/alpine", "3", false},
		{"alpine", "docker.io", "library/alpine", "latest", false},
		{"hub.foundries.io/factory/app", "hub.foundries.io", "factory/app", "latest", false},
	}
	for _, c := range cases {
		h, r, tg, err := parseImageRef(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("parseImageRef(%q) err=%v want %v", c.in, err, c.wantErr)
			continue
		}
		if h != c.host || r != c.repo || tg != c.tag {
			t.Errorf("parseImageRef(%q) = (%q, %q, %q) want (%q, %q, %q)",
				c.in, h, r, tg, c.host, c.repo, c.tag)
		}
	}
}

func TestParseBearerChallenge(t *testing.T) {
	r, s := parseBearerChallenge(`Bearer realm="https://gw/token",service="tuf-registry",scope="repository:demo/hello:pull"`)
	if r != "https://gw/token" || s != "tuf-registry" {
		t.Errorf("parseBearerChallenge: got (%q, %q)", r, s)
	}
	// Missing scheme should return empty.
	r, s = parseBearerChallenge(`Basic realm="api"`)
	if r != "" || s != "" {
		t.Errorf("parseBearerChallenge (non-bearer): got (%q, %q), want empty", r, s)
	}
}

// fakeRegistry stands in for a minimal docker-distribution server:
// - /v2/ returns 401 with a Bearer challenge
// - /token returns a static JWT for Basic-auth callers
// - /v2/<repo>/blobs/uploads/ returns 202 + Location
// - the resulting upload PUT returns 201 Created
// - manifest PUT returns 201 Created
// - manifest HEAD returns 200 + Docker-Content-Digest (for image pinning).
func TestPushOCIArtifactAndPinning(t *testing.T) {
	// Wire token + registry on a single server; the WWW-Authenticate
	// realm just points back at ourselves.
	var blobsReceived int
	var manifestReceived int
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			auth := r.Header.Get("Authorization")
			if auth == "" {
				w.Header().Set("Www-Authenticate",
					`Bearer realm="`+srv.URL+`/token",service="tuf-registry"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/token":
			// Require basic auth so we exercise the credential flow.
			user, pass, ok := r.BasicAuth()
			if !ok || user != "admin" || pass != "secret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "fake-jwt-token"})
		case strings.HasPrefix(r.URL.Path, "/v2/") && strings.HasSuffix(r.URL.Path, "/blobs/uploads/") && r.Method == "POST":
			loc := strings.Replace(r.URL.Path, "/blobs/uploads/", "/blobs/uploads/abc123", 1)
			w.Header().Set("Location", srv.URL+loc)
			w.WriteHeader(http.StatusAccepted)
		case strings.Contains(r.URL.Path, "/blobs/uploads/") && r.Method == "PUT":
			blobsReceived++
			w.WriteHeader(http.StatusCreated)
		case strings.Contains(r.URL.Path, "/manifests/") && r.Method == "PUT":
			manifestReceived++
			w.WriteHeader(http.StatusCreated)
		case strings.Contains(r.URL.Path, "/manifests/") && r.Method == "HEAD":
			// Image pinning lookup: serve a stable Docker-Content-Digest.
			w.Header().Set("Docker-Content-Digest", "sha256:"+strings.Repeat("a", 64))
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(r.URL.Path, "/v2/") && strings.Contains(r.URL.Path, "/blobs/") && r.Method == "HEAD":
			// Blob pre-check: pretend the blob does not yet exist.
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// httptest TLS uses an unverifiable cert. Swap in a permissive
	// http.DefaultClient for the duration of the test.
	saved := http.DefaultClient
	http.DefaultClient = &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	defer func() { http.DefaultClient = saved }()

	parsedURL, _ := url.Parse(srv.URL)
	registryHost := parsedURL.Host

	ctx := context.Background()

	// Push artifact.
	digest, ref, err := pushOCIArtifact(ctx, srv.URL, "demo/hello", "1",
		[]byte("fake-tarball"), "admin", "secret")
	if err != nil {
		t.Fatalf("pushOCIArtifact: %v", err)
	}
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
		t.Errorf("digest looks wrong: %q", digest)
	}
	if !strings.Contains(ref, registryHost+"/demo/hello@") {
		t.Errorf("ref %q does not contain expected prefix", ref)
	}
	if blobsReceived != 2 {
		t.Errorf("expected 2 blob uploads (config+layer), got %d", blobsReceived)
	}
	if manifestReceived != 1 {
		t.Errorf("expected 1 manifest PUT, got %d", manifestReceived)
	}

	// Test image pinning: input compose YAML with a tag-ref pointing
	// at the same registry should come back digest-pinned.
	composeIn := []byte(`services:
  app:
    image: ` + registryHost + `/demo/foo:v1
    restart: "no"
`)
	pinned, err := pinComposeServiceImages(ctx, composeIn, registryHost, "admin", "secret")
	if err != nil {
		t.Fatalf("pinComposeServiceImages: %v", err)
	}
	if !strings.Contains(string(pinned), "@sha256:") {
		t.Errorf("pinned compose missing digest: %s", string(pinned))
	}
	if strings.Contains(string(pinned), "/demo/foo:v1") {
		t.Errorf("pinned compose still has tag ref: %s", string(pinned))
	}
}

// TestPinComposePreservesAlreadyPinned exercises the early-return path
// when an image is already digest-pinned. No registry call needed.
func TestPinComposePreservesAlreadyPinned(t *testing.T) {
	in := []byte(`services:
  app:
    image: registry.example:5000/demo/foo@sha256:abcd
`)
	out, err := pinComposeServiceImages(context.Background(), in, "registry.example:5000", "admin", "secret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(string(out), "@sha256:abcd") {
		t.Errorf("digest-pinned image was rewritten: %s", string(out))
	}
}

// Sanity: indentLines + truncate (small helpers used by the publish
// progress output and error formatting).
func TestSmallHelpers(t *testing.T) {
	got := indentLines("a\nb\n", "  ")
	if got != "  a\n  b\n" {
		t.Errorf("indentLines: got %q", got)
	}
	if truncate("hello", 10) != "hello" {
		t.Error("truncate short")
	}
	if !strings.HasSuffix(truncate("hello world", 5), "(truncated)") {
		t.Error("truncate long")
	}
	// Use io.Discard import so the file compiles even when the
	// real-network code paths are skipped.
	_ = io.Discard
}
