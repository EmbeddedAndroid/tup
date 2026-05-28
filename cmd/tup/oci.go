package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

// OCI compose-app artifact publish for the on-prem stack.
//
// The on-device puller (composectl, in stock LmP images) only knows how
// to fetch compose-apps as OCI artifacts from a v2 distribution registry.
// It validates the single layer's mediaType == "application/octet-stream"
// and refuses anything else. So `tup compose-publish` must push the
// compose-app dir as an OCI artifact to the registry, not as a tarball
// served from a devgw URL.
//
// Artifact layout:
//
//	manifest (application/vnd.oci.image.manifest.v1+json)
//	  config (application/vnd.oci.image.config.v1+json) = "{}"
//	  layer  (application/octet-stream)                 = tar.gz of compose-app dir

const (
	ociManifestMediaType = "application/vnd.oci.image.manifest.v1+json"
	ociConfigMediaType   = "application/vnd.oci.image.config.v1+json"
	ociLayerMediaType    = "application/octet-stream"
)

type ociManifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Config        ociDescriptor     `json:"config"`
	Layers        []ociDescriptor   `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

type ociDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// composeAppManifestVersion is the value aktualizr-lite's
// docker::Manifest verifier expects in annotations["compose-app"].
// Pinned at "v1" in upstream aktualizr-lite/src/docker/docker.h
// (constexpr Version{"v1"}). Without this annotation aktualizr-lite
// throws "Got invalid App manifest, missing a manifest version"
// the first time isFetched() inspects a freshly-pulled artifact —
// devices with an existing cache skip the check and don't notice,
// so the bug only surfaces on fresh fetches (re-register, wipe).
const composeAppManifestVersion = "v1"

// pushOCIArtifact publishes a compose-app as an OCI artifact to
// <registry>/<repo>@sha256:<manifest-digest>.
//
// Registry auth: standard v2 token-bearer flow. The first request to
// /v2/<repo>/blobs/uploads/ receives 401 + a WWW-Authenticate: Bearer
// challenge naming the realm + service + scope. The caller follows the
// challenge with Basic auth ($basicUser:$basicPass), receives a JWT,
// and retries with Authorization: Bearer <jwt>.
//
// For our stack basicUser="admin" + basicPass=<tufd admin token>;
// devgw at :9200/token proxies to tufd's /token issuer.
//
// Returns the manifest digest (sha256:hex) and the human-readable
// reference (<host>/<repo>@<digest>).
func pushOCIArtifact(
	ctx context.Context,
	registryHost string, // e.g. "192.168.1.109:5000"
	repo string, // e.g. "demo/hello"
	tag string, // e.g. "latest" or "1779655868"
	layerBlob []byte, // the tar.gz of the compose-app dir
	basicUser, basicPass string, // admin token credentials for the token-realm
) (digest string, ref string, err error) {
	// Default to HTTPS — the docker-distribution registry serves TLS
	// on its address by default, and stock LmP composectl only pulls
	// over HTTPS. Operator can pass `http://host:port` for local-only
	// testing if their registry is configured for plaintext.
	scheme := "https"
	host := registryHost
	if strings.Contains(registryHost, "://") {
		u, perr := url.Parse(registryHost)
		if perr != nil {
			return "", "", fmt.Errorf("parse registryHost: %w", perr)
		}
		scheme = u.Scheme
		host = u.Host
	}

	base := scheme + "://" + host

	// Step 1: build the config blob. Minimal valid JSON; composectl
	// reads the manifest's config descriptor but does not enforce the
	// config blob's contents.
	configBytes := []byte("{}")
	configDigest := sha256Hex(configBytes)

	// Step 2: layer digest is already known from layerBlob.
	layerDigest := sha256Hex(layerBlob)

	// Step 3: build the manifest. Marshal canonical (sorted keys) so the
	// digest is stable.
	manifest := ociManifest{
		SchemaVersion: 2,
		MediaType:     ociManifestMediaType,
		Config: ociDescriptor{
			MediaType: ociConfigMediaType,
			Digest:    "sha256:" + configDigest,
			Size:      int64(len(configBytes)),
		},
		Layers: []ociDescriptor{
			{
				MediaType: ociLayerMediaType,
				Digest:    "sha256:" + layerDigest,
				Size:      int64(len(layerBlob)),
			},
		},
		Annotations: map[string]string{
			// aktualizr-lite's docker::Manifest verifier requires this
			// exact annotation key + value. Without it isFetched()
			// throws "Got invalid App manifest, missing a manifest
			// version" the first time it inspects a freshly-pulled
			// artifact. Devices with a "trusted" prior cache skip the
			// check and don't notice the gap, so this bug only
			// surfaces on a fresh fetch (sql.db wipe / re-register).
			"compose-app": composeAppManifestVersion,
		},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return "", "", fmt.Errorf("marshal manifest: %w", err)
	}
	manifestDigest := sha256Hex(manifestBytes)

	// Step 4: probe a blob upload to learn the auth realm.
	scope := fmt.Sprintf("repository:%s:push,pull", repo)
	bearer, err := obtainRegistryToken(ctx, base, repo, scope, basicUser, basicPass)
	if err != nil {
		return "", "", fmt.Errorf("registry auth: %w", err)
	}

	// Step 5: upload the config blob.
	if err := putBlob(ctx, base, repo, "sha256:"+configDigest, ociConfigMediaType, configBytes, bearer); err != nil {
		return "", "", fmt.Errorf("upload config blob: %w", err)
	}

	// Step 6: upload the layer blob.
	if err := putBlob(ctx, base, repo, "sha256:"+layerDigest, ociLayerMediaType, layerBlob, bearer); err != nil {
		return "", "", fmt.Errorf("upload layer blob: %w", err)
	}

	// Step 7: PUT the manifest under the tag.
	mURL := fmt.Sprintf("%s/v2/%s/manifests/%s", base, repo, tag)
	req, err := http.NewRequestWithContext(ctx, "PUT", mURL, bytes.NewReader(manifestBytes))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", ociManifestMediaType)
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("PUT manifest: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("PUT manifest: status=%d body=%s", resp.StatusCode, truncate(string(body), 400))
	}

	digest = "sha256:" + manifestDigest
	ref = fmt.Sprintf("%s/%s@%s", host, repo, digest)
	return digest, ref, nil
}

// obtainRegistryToken hits /v2/ on the registry, parses the
// WWW-Authenticate: Bearer challenge, then GETs the realm with Basic
// auth and returns the JWT bearer.
func obtainRegistryToken(ctx context.Context, base, repo, scope, basicUser, basicPass string) (string, error) {
	// Probe /v2/ for the challenge.
	req, err := http.NewRequestWithContext(ctx, "GET", base+"/v2/", nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("probe /v2/: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		// Registry may be open or already authorized; assume no bearer
		// needed.
		return "", nil
	}
	wwwAuth := resp.Header.Get("Www-Authenticate")
	realm, service := parseBearerChallenge(wwwAuth)
	if realm == "" {
		return "", fmt.Errorf("no Bearer realm in WWW-Authenticate=%q", wwwAuth)
	}

	// Fetch the token from realm.
	q := url.Values{}
	if service != "" {
		q.Set("service", service)
	}
	q.Set("scope", scope)
	tokenURL := realm + "?" + q.Encode()
	treq, err := http.NewRequestWithContext(ctx, "GET", tokenURL, nil)
	if err != nil {
		return "", err
	}
	treq.SetBasicAuth(basicUser, basicPass)

	// The token realm is normally HTTPS with stack-CA cert. We trust
	// the system bundle (which on the operator host will have stack-CA
	// appended after step 3 of the migration). If it fails, surface the
	// error verbatim — operator knows the trust state of their machine.
	tresp, err := http.DefaultClient.Do(treq)
	if err != nil {
		return "", fmt.Errorf("GET token realm %s: %w", realm, err)
	}
	defer tresp.Body.Close()
	if tresp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tresp.Body)
		return "", fmt.Errorf("token realm returned status=%d body=%s", tresp.StatusCode, truncate(string(body), 400))
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tresp.Body).Decode(&tok); err != nil {
		return "", fmt.Errorf("decode token: %w", err)
	}
	if tok.Token != "" {
		return tok.Token, nil
	}
	if tok.AccessToken != "" {
		return tok.AccessToken, nil
	}
	return "", fmt.Errorf("token realm returned no token field")
}

// putBlob uploads a single blob via the monolithic POST→PUT flow. We
// skip the chunked upload path (POST→PATCH×N→PUT) because compose-app
// layers are small (a few MB at most).
func putBlob(ctx context.Context, base, repo, digest, mediaType string, body []byte, bearer string) error {
	// Pre-check: does the blob already exist? Skips re-upload if a
	// previous publish already pushed it (e.g. when re-publishing the
	// same compose-app).
	headURL := fmt.Sprintf("%s/v2/%s/blobs/%s", base, repo, digest)
	hreq, _ := http.NewRequestWithContext(ctx, "HEAD", headURL, nil)
	if bearer != "" {
		hreq.Header.Set("Authorization", "Bearer "+bearer)
	}
	hresp, err := http.DefaultClient.Do(hreq)
	if err == nil {
		hresp.Body.Close()
		if hresp.StatusCode == http.StatusOK {
			return nil
		}
	}

	// POST to start an upload session.
	postURL := fmt.Sprintf("%s/v2/%s/blobs/uploads/", base, repo)
	preq, err := http.NewRequestWithContext(ctx, "POST", postURL, nil)
	if err != nil {
		return err
	}
	if bearer != "" {
		preq.Header.Set("Authorization", "Bearer "+bearer)
	}
	presp, err := http.DefaultClient.Do(preq)
	if err != nil {
		return fmt.Errorf("POST uploads: %w", err)
	}
	defer presp.Body.Close()
	if presp.StatusCode != http.StatusAccepted {
		out, _ := io.ReadAll(presp.Body)
		return fmt.Errorf("POST uploads status=%d body=%s", presp.StatusCode, truncate(string(out), 200))
	}
	loc := presp.Header.Get("Location")
	if loc == "" {
		return fmt.Errorf("POST uploads returned no Location header")
	}
	if strings.HasPrefix(loc, "/") {
		// Registry sometimes returns a relative path; absolute-ize.
		loc = base + loc
	}

	// Append digest query param. Some registries already include
	// query string; honor it.
	sep := "?"
	if strings.Contains(loc, "?") {
		sep = "&"
	}
	putURL := loc + sep + "digest=" + url.QueryEscape(digest)

	preq2, err := http.NewRequestWithContext(ctx, "PUT", putURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	preq2.Header.Set("Content-Type", mediaType)
	preq2.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	if bearer != "" {
		preq2.Header.Set("Authorization", "Bearer "+bearer)
	}
	presp2, err := http.DefaultClient.Do(preq2)
	if err != nil {
		return fmt.Errorf("PUT blob: %w", err)
	}
	defer presp2.Body.Close()
	if presp2.StatusCode != http.StatusCreated && presp2.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(presp2.Body)
		return fmt.Errorf("PUT blob status=%d body=%s", presp2.StatusCode, truncate(string(out), 200))
	}
	return nil
}

// parseBearerChallenge extracts realm="..." and service="..." values
// from a WWW-Authenticate: Bearer header. We do a minimal hand-rolled
// parse (no quote-pair escaping support); the values we receive come
// from our own registry config and don't contain quotes.
func parseBearerChallenge(header string) (realm, service string) {
	idx := strings.Index(strings.ToLower(header), "bearer ")
	if idx < 0 {
		return "", ""
	}
	rest := header[idx+len("bearer "):]
	for _, part := range strings.Split(rest, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		v := strings.Trim(strings.TrimSpace(kv[1]), `"`)
		switch k {
		case "realm":
			realm = v
		case "service":
			service = v
		}
	}
	return realm, service
}

// pinComposeServiceImages walks a docker-compose YAML, resolves each
// service's `image:` tag to a digest via the registry, and returns the
// rewritten YAML with `image: foo/bar@sha256:...` references. composectl
// refuses to pull a compose-app whose service images aren't digest-pinned
// (error: "unsupported image reference format; digest is required").
//
// Pinning only applies to images that live in the SAME registry as the
// push target (host match). Cross-registry pinning would need separate
// credentials — skip those with a warning and let composectl error out
// if it really does require them.
func pinComposeServiceImages(ctx context.Context, composeBytes []byte, registryHost, basicUser, basicPass string) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(composeBytes, &doc); err != nil {
		return nil, fmt.Errorf("parse compose yaml: %w", err)
	}
	// Top is a Document node wrapping a mapping.
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil, fmt.Errorf("compose yaml: unexpected root shape")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("compose yaml: root is not a mapping")
	}

	// Find the "services:" key.
	var services *yaml.Node
	for i := 0; i < len(root.Content); i += 2 {
		k := root.Content[i]
		if k.Value == "services" {
			services = root.Content[i+1]
			break
		}
	}
	if services == nil {
		return nil, fmt.Errorf("compose yaml: no top-level services: key")
	}
	if services.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("compose yaml: services: is not a mapping")
	}

	// Walk each service.
	for i := 0; i < len(services.Content); i += 2 {
		svcName := services.Content[i].Value
		svc := services.Content[i+1]
		if svc.Kind != yaml.MappingNode {
			continue
		}
		var imageNode *yaml.Node
		for j := 0; j < len(svc.Content); j += 2 {
			if svc.Content[j].Value == "image" {
				imageNode = svc.Content[j+1]
				break
			}
		}
		if imageNode == nil {
			continue
		}
		ref := imageNode.Value
		// Already digest-pinned? Skip.
		if strings.Contains(ref, "@sha256:") {
			continue
		}

		host, repo, tag, err := parseImageRef(ref)
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", svcName, err)
		}
		// Only pin against the target registry. Cross-registry images
		// (e.g. docker.io/library/redis:7) need credentials we don't
		// have at compose-publish time; leave them alone.
		if host != registryHost {
			fmt.Fprintf(io.Discard, "skipping cross-registry pin for %s\n", ref)
			continue
		}

		// Per-repo token: registries scope bearer tokens to the
		// requested repository, so a token minted for the compose-app
		// artifact's repo cannot HEAD a different repo. Mint a fresh
		// pull-only token for each service image.
		bearer, err := obtainRegistryToken(ctx, "https://"+host, repo,
			fmt.Sprintf("repository:%s:pull", repo), basicUser, basicPass)
		if err != nil {
			return nil, fmt.Errorf("service %s: token for %s: %w", svcName, ref, err)
		}
		digest, err := resolveTagToDigest(ctx, host, repo, tag, bearer)
		if err != nil {
			return nil, fmt.Errorf("service %s: resolve %s: %w", svcName, ref, err)
		}
		imageNode.Value = host + "/" + repo + "@" + digest
		imageNode.Tag = "!!str"
		imageNode.Style = 0
	}

	out, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, fmt.Errorf("marshal pinned compose yaml: %w", err)
	}
	return out, nil
}

// parseImageRef splits an image reference into (host, repo, tag).
// Supports `host[:port]/repo[:tag]` and bare `repo[:tag]` (treated as
// docker.io/library/repo:tag).
func parseImageRef(ref string) (host, repo, tag string, err error) {
	// Detect host part: must contain '.' or ':' before the first '/'.
	slash := strings.Index(ref, "/")
	if slash > 0 && (strings.Contains(ref[:slash], ".") || strings.Contains(ref[:slash], ":")) {
		host = ref[:slash]
		ref = ref[slash+1:]
	} else {
		host = "docker.io"
		if !strings.Contains(ref, "/") {
			ref = "library/" + ref
		}
	}
	if i := strings.LastIndex(ref, ":"); i > 0 {
		tag = ref[i+1:]
		repo = ref[:i]
	} else {
		tag = "latest"
		repo = ref
	}
	if repo == "" || tag == "" {
		return "", "", "", fmt.Errorf("malformed image reference %q", ref)
	}
	return host, repo, tag, nil
}

// resolveTagToDigest HEADs /v2/<repo>/manifests/<tag> and returns the
// canonical Docker-Content-Digest header value.
func resolveTagToDigest(ctx context.Context, host, repo, tag, bearer string) (string, error) {
	// Manifests may be docker schema2, OCI manifest, or manifest-list /
	// image-index. We ask for all and let the registry pick.
	manifestAccept := strings.Join([]string{
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.oci.image.index.v1+json",
	}, ", ")

	url := "https://" + host + "/v2/" + repo + "/manifests/" + tag
	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", manifestAccept)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("HEAD manifest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		d := resp.Header.Get("Docker-Content-Digest")
		if d != "" {
			return d, nil
		}
	}
	return "", fmt.Errorf("HEAD %s status=%d (no Docker-Content-Digest)", url, resp.StatusCode)
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func indentLines(s, prefix string) string {
	if s == "" {
		return ""
	}
	lines := strings.SplitAfter(s, "\n")
	var b strings.Builder
	for _, l := range lines {
		if l == "" {
			continue
		}
		b.WriteString(prefix)
		b.WriteString(l)
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
