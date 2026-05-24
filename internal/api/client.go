// Package api is tup's HTTP client for the tufd backend.
// Exact wire shape — no transformations, no caching, no retries.
// tup is a thin orchestrator; everything interesting happens server-side.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// Factory matches tufd's NamespaceListEntry (wire-compat name; the
// public CLI subcommand is `namespace`).
type Factory struct {
	ProjectID            string `json:"project_id"`
	Name              string `json:"name"`
	LatestRootVersion int    `json:"latest_root_version"`
	RootKeyID         string `json:"root_keyid,omitempty"`
}

type CreateRequest struct {
	Name    string `json:"name,omitempty"`
	KeyType string `json:"key_type,omitempty"`
}

type CreateResponse struct {
	ProjectID      string `json:"project_id"`
	Name        string `json:"name"`
	RootKeyID   string `json:"root_keyid"`
	RootVersion int    `json:"root_version"`
}

func (c *Client) ListNamespaces(ctx context.Context) ([]Factory, error) {
	resp, err := c.do(ctx, http.MethodGet, "/api/v1/user_repo", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusErr("list namespaces", resp)
	}
	var out struct {
		Factories []Factory `json:"factories"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("api: decode list: %w", err)
	}
	return out.Factories, nil
}

func (c *Client) CreateNamespace(ctx context.Context, req CreateRequest) (*CreateResponse, error) {
	body, _ := json.Marshal(req)
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/user_repo", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return nil, statusErr("create namespace", resp)
	}
	var out CreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("api: decode create: %w", err)
	}
	return &out, nil
}

// PublishRequest matches tufd's PublishRequest body shape.
type PublishRequest struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	HardwareIDs  []string          `json:"hardware_ids,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	TargetFormat string            `json:"target_format,omitempty"`
	SHA256       string            `json:"sha256"`
	Length       int64             `json:"length,omitempty"`
	URI          string            `json:"uri,omitempty"`
	OrigURI      string            `json:"orig_uri,omitempty"`
	ImageFile    string            `json:"image_file,omitempty"`
	ComposeApps  map[string]string `json:"compose_apps,omitempty"`

	// LmP build provenance (optional).
	LMPVer                     string `json:"lmp_ver,omitempty"`
	LMPManifestSHA             string `json:"lmp_manifest_sha,omitempty"`
	MetaSubscriberOverridesSHA string `json:"meta_subscriber_overrides_sha,omitempty"`
	ContainersSHA              string `json:"containers_sha,omitempty"`
}

// PublishResponse matches tufd's publisher.Response shape.
type PublishResponse struct {
	TargetKey        string `json:"target_key"`
	TargetsVersion   int    `json:"targets_version"`
	SnapshotVersion  int    `json:"snapshot_version"`
	TimestampVersion int    `json:"timestamp_version"`
}

// RotateRootResponse mirrors tufd's rotator.Response shape.
type RotateRootResponse struct {
	NewRootVersion   int    `json:"new_root_version"`
	NewRootKeyID     string `json:"new_root_keyid"`
	PriorRootKeyID   string `json:"prior_root_keyid"`
	PriorRootVersion int    `json:"prior_root_version"`
}

// RotateRootRequest matches tufd's RotateRootRequest body shape. KeyType
// is optional; empty inherits the current key's algorithm.
type RotateRootRequest struct {
	KeyType string `json:"key_type,omitempty"`
}

// BootstrapStageRequest creates a new namespace with a customer-held
// offline root key. Server mints the targets/snapshot/timestamp online
// keys and stages a candidate Root v=1; customer signs offline; POSTs
// the envelope back via BootstrapFinalize.
type BootstrapStageRequest struct {
	Name             string `json:"name"`
	RootPublicKeyPEM string `json:"root_pubkey_pem"`
	RootKeyType      string `json:"root_keytype,omitempty"`
	RootScheme       string `json:"root_scheme,omitempty"`
}

// BootstrapStageResponse mirrors tufd's BeginExternalRootResponse.
type BootstrapStageResponse struct {
	StagingID      string   `json:"staging_id"`
	ProjectID         string   `json:"project_id"`
	Name           string   `json:"name"`
	RootKeyID      string   `json:"root_keyid"`
	TargetsKeyID   string   `json:"targets_keyid"`
	SnapshotKeyID  string   `json:"snapshot_keyid"`
	TimestampKeyID string   `json:"timestamp_keyid"`
	BytesToSign    []byte   `json:"bytes_to_sign"`
	RequiredKeyIDs []string `json:"required_keyids"`
	ExpiresAt      string   `json:"expires_at"`
}

// BootstrapStage POSTs to /api/v1/user_repo/_bootstrap-stage. The
// namespace is NOT yet visible to /api/v1/user_repo until
// BootstrapFinalize completes.
func (c *Client) BootstrapStage(ctx context.Context, req BootstrapStageRequest) (*BootstrapStageResponse, error) {
	body, _ := json.Marshal(req)
	resp, err := c.do(ctx, http.MethodPost,
		"/api/v1/user_repo/_bootstrap-stage", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return nil, statusErr("bootstrap stage", resp)
	}
	var out BootstrapStageResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("api: decode bootstrap stage: %w", err)
	}
	return &out, nil
}

// BootstrapFinalizeRequest carries the signed envelope back.
type BootstrapFinalizeRequest struct {
	StagingID string `json:"staging_id"`
	Envelope  []byte `json:"envelope"`
}

// BootstrapFinalize POSTs the signed envelope; on success the
// namespace is live. Response is the standard CreateResponse shape.
func (c *Client) BootstrapFinalize(ctx context.Context, req BootstrapFinalizeRequest) (*CreateResponse, error) {
	body, _ := json.Marshal(req)
	resp, err := c.do(ctx, http.MethodPost,
		"/api/v1/user_repo/_bootstrap-finalize", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return nil, statusErr("bootstrap finalize", resp)
	}
	var out CreateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("api: decode bootstrap finalize: %w", err)
	}
	return &out, nil
}

// StageRotationRequest matches tufd's offline-stage body.
type StageRotationRequest struct {
	NewPublicKeyPEM string `json:"new_pubkey_pem"`
	NewKeyType      string `json:"new_keytype,omitempty"`
	NewScheme       string `json:"new_scheme,omitempty"`
}

// StageRotationResponse matches tufd's offline-stage response. Bytes to
// sign come back as raw JSON bytes (base64-encoded over the wire by
// the JSON encoder — Go's json.Unmarshal of []byte handles it).
type StageRotationResponse struct {
	StagingID      string   `json:"staging_id"`
	NewRootVersion int      `json:"new_root_version"`
	NewRootKeyID   string   `json:"new_root_keyid"`
	PriorRootKeyID string   `json:"prior_root_keyid"`
	BytesToSign    []byte   `json:"bytes_to_sign"`
	RequiredKeyIDs []string `json:"required_keyids"`
	ExpiresAt      string   `json:"expires_at"`
}

// StageRotation hits POST /root/stage; the returned BytesToSign is
// exactly what the customer must sign with both old and new private
// keys, byte-for-byte, no re-canonicalization.
func (c *Client) StageRotation(ctx context.Context, repoID string, req StageRotationRequest) (*StageRotationResponse, error) {
	body, _ := json.Marshal(req)
	resp, err := c.do(ctx, http.MethodPost,
		"/api/v1/user_repo/"+repoID+"/root/stage", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return nil, statusErr("stage rotation", resp)
	}
	var out StageRotationResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("api: decode stage: %w", err)
	}
	return &out, nil
}

// FinalizeRotationRequest matches tufd's offline-finalize body. The
// envelope is the raw bytes of the {signatures, signed} JSON the
// customer produced offline.
type FinalizeRotationRequest struct {
	StagingID string `json:"staging_id"`
	Envelope  []byte `json:"envelope"`
}

// FinalizeRotation POSTs the offline-signed envelope and returns the
// finalized rotation state. Reuses RotateRootResponse since the
// success shape is identical to the dual-key flow.
func (c *Client) FinalizeRotation(ctx context.Context, repoID string, req FinalizeRotationRequest) (*RotateRootResponse, error) {
	body, _ := json.Marshal(req)
	resp, err := c.do(ctx, http.MethodPost,
		"/api/v1/user_repo/"+repoID+"/root/finalize", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return nil, statusErr("finalize rotation", resp)
	}
	var out RotateRootResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("api: decode finalize: %w", err)
	}
	return &out, nil
}

// RegisterDeviceResponse mirrors tufd's device-register response.
type RegisterDeviceResponse struct {
	DeviceID string `json:"device_id"`
	ProjectID   string `json:"project_id"`
	CertPEM  string `json:"cert_pem"`
	KeyPEM   string `json:"key_pem"`
	CAPEM    string `json:"ca_pem"`
}

// RegisterDevice mints a client cert for deviceID under repoID.
// Returns cert + private key (PKCS#8 ed25519) + the namespace CA cert.
func (c *Client) RegisterDevice(ctx context.Context, repoID, deviceID string) (*RegisterDeviceResponse, error) {
	body, _ := json.Marshal(map[string]string{"device_id": deviceID})
	resp, err := c.do(ctx, http.MethodPost,
		"/api/v1/user_repo/"+repoID+"/devices", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return nil, statusErr("register device", resp)
	}
	var out RegisterDeviceResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("api: decode register-device: %w", err)
	}
	return &out, nil
}

// firstNonEmpty returns the first non-empty arg. Used to pick the
// admin token from env vars with reasonable fallbacks.
func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// ExportedRoleKey mirrors tufd's handleExportRoleKey response shape.
type ExportedRoleKey struct {
	Role    string
	KID     string
	KeyType string
	Public  string
	Private string
}

// ExportRoleKey fetches a role's private key in AtsKey JSON form so
// the operator can pack a fioctl-compatible offline-creds.tgz tarball.
// Requires TUP_ADMIN_TOKEN env (or TUFD_ADMIN_TOKEN) to authenticate
// — the endpoint is guarded server-side because it exposes private
// key material.
func (c *Client) ExportRoleKey(ctx context.Context, repoID, role string) (*ExportedRoleKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.BaseURL+"/api/v1/user_repo/"+repoID+"/keys/"+role+"/export", nil)
	if err != nil {
		return nil, err
	}
	if tok := firstNonEmpty(os.Getenv("TUP_ADMIN_TOKEN"), os.Getenv("TUFD_ADMIN_TOKEN")); tok != "" {
		req.Header.Set("OSF-TOKEN", tok)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusErr("export role key", resp)
	}
	var raw struct {
		Role    string `json:"role"`
		KID     string `json:"kid"`
		KeyType string `json:"keytype"`
		KeyVal  struct {
			Public  string `json:"public"`
			Private string `json:"private"`
		} `json:"keyval"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("api: decode export-role-key: %w", err)
	}
	return &ExportedRoleKey{
		Role:    raw.Role,
		KID:     raw.KID,
		KeyType: raw.KeyType,
		Public:  raw.KeyVal.Public,
		Private: raw.KeyVal.Private,
	}, nil
}

// GetCA returns the namespace's device-CA cert PEM. devgw uses this
// to verify incoming device client certs over mTLS.
func (c *Client) GetCA(ctx context.Context, repoID string) ([]byte, error) {
	resp, err := c.do(ctx, http.MethodGet,
		"/api/v1/user_repo/"+repoID+"/ca.crt", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusErr("get CA", resp)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("api: read CA: %w", err)
	}
	return body, nil
}

// DevicePin mirrors tufd's repostore.DevicePin shape (subset used
// by the CLI).
type DevicePin struct {
	DeviceID  string `json:"device_id"`
	TargetKey string `json:"target_key"`
	PinnedAt  int64  `json:"pinned_at"`
	PinnedBy  string `json:"pinned_by"`
}

// PinDevice records a (device, target) pin in the namespace.
// Idempotent — re-pinning the same pair is a no-op server-side.
func (c *Client) PinDevice(ctx context.Context, repoID, deviceID, targetKey, pinnedBy string) error {
	body, _ := json.Marshal(map[string]string{
		"target_key": targetKey, "pinned_by": pinnedBy,
	})
	resp, err := c.do(ctx, http.MethodPost,
		"/api/v1/user_repo/"+repoID+"/devices/"+deviceID+"/pins", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return statusErr("pin device", resp)
	}
	return nil
}

// UnpinDevice removes pins for a device. When targetKey is empty,
// removes ALL pins for the device. Returns the count removed.
func (c *Client) UnpinDevice(ctx context.Context, repoID, deviceID, targetKey string) (int, error) {
	path := "/api/v1/user_repo/" + repoID + "/devices/" + deviceID + "/pins"
	if targetKey != "" {
		path = path + "/" + targetKey
	}
	resp, err := c.do(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, nil
	}
	if resp.StatusCode != http.StatusOK {
		return 0, statusErr("unpin device", resp)
	}
	var body struct {
		Removed int `json:"removed"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return body.Removed, nil
}

// ListPins returns pins in the namespace (all devices, or filtered
// when deviceID is set).
func (c *Client) ListPins(ctx context.Context, repoID, deviceID string) ([]DevicePin, error) {
	var path string
	if deviceID == "" {
		path = "/api/v1/user_repo/" + repoID + "/pins"
	} else {
		path = "/api/v1/user_repo/" + repoID + "/devices/" + deviceID + "/pins"
	}
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusErr("list pins", resp)
	}
	if deviceID != "" {
		var body struct {
			TargetKeys []string `json:"target_keys"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		out := make([]DevicePin, 0, len(body.TargetKeys))
		for _, k := range body.TargetKeys {
			out = append(out, DevicePin{DeviceID: deviceID, TargetKey: k})
		}
		return out, nil
	}
	var body struct {
		Pins []DevicePin `json:"pins"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return body.Pins, nil
}

// OstreePushStats is a summary of one ostree-push run for the CLI.
type OstreePushStats struct {
	Total    int
	Uploaded int
	Skipped  int
	Errors   int
	Bytes    int64
}

// OstreeInit calls POST /ostree/init to ensure the per-namespace repo
// directory + config exists. Idempotent on the server.
func (c *Client) OstreeInit(ctx context.Context, repoID, adminToken string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/api/v1/user_repo/"+repoID+"/ostree/init", nil)
	if adminToken != "" {
		req.Header.Set("OSF-TOKEN", adminToken)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return statusErr("ostree init", resp)
	}
	return nil
}

// OstreeHasObject is the HEAD-side check tup runs to skip already-
// uploaded objects (cheap dedup).
func (c *Client) OstreeHasObject(ctx context.Context, repoID, sha2, rest, adminToken string) bool {
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead,
		c.BaseURL+"/api/v1/user_repo/"+repoID+"/ostree/objects/"+sha2+"/"+rest, nil)
	if adminToken != "" {
		req.Header.Set("OSF-TOKEN", adminToken)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// OstreePutObject streams one ostree object's bytes to the server.
// sha2 is the first two hex chars of the object hash, rest is the
// remaining 58 hex chars + ".{commit,filez,dirtree,...}" extension.
func (c *Client) OstreePutObject(ctx context.Context, repoID, sha2, rest, adminToken string, body io.Reader, size int64) (created bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/api/v1/user_repo/"+repoID+"/ostree/objects/"+sha2+"/"+rest, body)
	if err != nil {
		return false, err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	if adminToken != "" {
		req.Header.Set("OSF-TOKEN", adminToken)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusCreated:
		return true, nil
	case http.StatusOK:
		return false, nil
	default:
		return false, statusErr("ostree put object", resp)
	}
}

// OstreePutRef writes refs/heads/<branch> = <commitSha>.
func (c *Client) OstreePutRef(ctx context.Context, repoID, branch, commitSha, adminToken string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut,
		c.BaseURL+"/api/v1/user_repo/"+repoID+"/ostree/refs/heads/"+branch,
		bytes.NewReader([]byte(commitSha+"\n")))
	req.Header.Set("Content-Type", "text/plain")
	if adminToken != "" {
		req.Header.Set("OSF-TOKEN", adminToken)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return statusErr("ostree put ref", resp)
	}
	return nil
}

// OstreePushRepo walks a local archive repo + POSTs every object,
// then PUTs each branch ref. Concurrent uploads with HEAD-dedup.
// Returns counts + a single error from the last failed object (caller
// can choose to abort or continue based on the failures count).
func (c *Client) OstreePushRepo(ctx context.Context, repoID, adminToken, localRepo, branch string, concurrency int, progress func(stats OstreePushStats)) (OstreePushStats, error) {
	if err := c.OstreeInit(ctx, repoID, adminToken); err != nil {
		return OstreePushStats{}, fmt.Errorf("init: %w", err)
	}

	// 1. Enumerate every object file.
	objectsRoot := filepath.Join(localRepo, "objects")
	type job struct{ sha2, rest, full string; size int64 }
	var jobs []job
	if err := filepath.Walk(objectsRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(objectsRoot, path)
		parts := strings.SplitN(rel, "/", 2)
		if len(parts) != 2 || len(parts[0]) != 2 {
			return nil
		}
		jobs = append(jobs, job{sha2: parts[0], rest: parts[1], full: path, size: info.Size()})
		return nil
	}); err != nil {
		return OstreePushStats{}, fmt.Errorf("walk objects: %w", err)
	}

	stats := OstreePushStats{Total: len(jobs)}
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func(j job) {
			defer func() { <-sem; wg.Done() }()
			if c.OstreeHasObject(ctx, repoID, j.sha2, j.rest, adminToken) {
				mu.Lock()
				stats.Skipped++
				if progress != nil {
					progress(stats)
				}
				mu.Unlock()
				return
			}
			f, err := os.Open(j.full)
			if err != nil {
				mu.Lock()
				stats.Errors++
				mu.Unlock()
				return
			}
			created, err := c.OstreePutObject(ctx, repoID, j.sha2, j.rest, adminToken, f, j.size)
			f.Close()
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				stats.Errors++
				return
			}
			if created {
				stats.Uploaded++
				stats.Bytes += j.size
			} else {
				stats.Skipped++
			}
			if progress != nil {
				progress(stats)
			}
		}(jobs[i])
	}
	wg.Wait()

	// 2. PUT refs. If branch is empty, walk every ref under refs/heads.
	refsRoot := filepath.Join(localRepo, "refs/heads")
	branches := map[string]string{}
	if branch != "" {
		sha, err := os.ReadFile(filepath.Join(refsRoot, branch))
		if err != nil {
			return stats, fmt.Errorf("read ref %s: %w", branch, err)
		}
		branches[branch] = strings.TrimSpace(string(sha))
	} else {
		_ = filepath.Walk(refsRoot, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(refsRoot, path)
			sha, err := os.ReadFile(path)
			if err == nil {
				branches[rel] = strings.TrimSpace(string(sha))
			}
			return nil
		})
	}
	for b, sha := range branches {
		if err := c.OstreePutRef(ctx, repoID, b, sha, adminToken); err != nil {
			return stats, fmt.Errorf("put ref %s: %w", b, err)
		}
	}
	return stats, nil
}

// Wave mirrors tufd's repostore.Wave.
type Wave struct {
	Name       string   `json:"name"`
	TargetKeys []string `json:"target_keys"`
	CreatedAt  int64    `json:"created_at,omitempty"`
	CreatedBy  string   `json:"created_by,omitempty"`
	Members    []string `json:"members,omitempty"`
	GroupID    *int64   `json:"group_id,omitempty"`
}

// WaveCreate creates or replaces a wave. groupID is optional: passing
// a non-nil value makes the wave group-scoped (dynamic membership
// follows devices.group_id matches); nil keeps the legacy explicit-
// list behavior driven by wave_members.
func (c *Client) WaveCreate(ctx context.Context, repoID, name string, targetKeys []string, by string, groupID *int64) error {
	payload := map[string]any{
		"name": name, "target_keys": targetKeys, "created_by": by,
	}
	if groupID != nil {
		payload["group_id"] = *groupID
	}
	body, _ := json.Marshal(payload)
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/user_repo/"+repoID+"/waves", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return statusErr("wave create", resp)
	}
	return nil
}

// DeviceGroup mirrors tufd's configstore.Group; minimal shape for
// "look up the group_id from a name" used by wave-create's --group
// flag.
type DeviceGroup struct {
	GroupID     int64  `json:"group_id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// GroupGetByName fetches the device group with the given name, or
// returns ErrNotFound if absent.
func (c *Client) GroupGetByName(ctx context.Context, repoID, name string) (*DeviceGroup, error) {
	resp, err := c.do(ctx, http.MethodGet, "/api/v1/user_repo/"+repoID+"/groups", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusErr("groups list", resp)
	}
	var body struct {
		Groups []DeviceGroup `json:"groups"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	for _, g := range body.Groups {
		if g.Name == name {
			return &g, nil
		}
	}
	return nil, fmt.Errorf("device group %q not found in project %s", name, repoID)
}

func (c *Client) WaveList(ctx context.Context, repoID string) ([]Wave, error) {
	resp, err := c.do(ctx, http.MethodGet, "/api/v1/user_repo/"+repoID+"/waves", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusErr("wave list", resp)
	}
	var body struct {
		Waves []Wave `json:"waves"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return body.Waves, nil
}

func (c *Client) WaveDelete(ctx context.Context, repoID, name string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/api/v1/user_repo/"+repoID+"/waves/"+name, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return statusErr("wave delete", resp)
	}
	return nil
}

func (c *Client) WaveAddMember(ctx context.Context, repoID, name, deviceID, by string) error {
	body, _ := json.Marshal(map[string]string{"device_id": deviceID, "added_by": by})
	resp, err := c.do(ctx, http.MethodPost,
		"/api/v1/user_repo/"+repoID+"/waves/"+name+"/members", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return statusErr("wave add member", resp)
	}
	return nil
}

func (c *Client) WaveRemoveMember(ctx context.Context, repoID, name, deviceID string) error {
	resp, err := c.do(ctx, http.MethodDelete,
		"/api/v1/user_repo/"+repoID+"/waves/"+name+"/members/"+deviceID, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return statusErr("wave remove member", resp)
	}
	return nil
}

// App mirrors tufd's appstore.App (subset used by the CLI).
type App struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	SHA256     string `json:"sha256"`
	Size       int64  `json:"size"`
	UploadedAt int64  `json:"uploaded_at,omitempty"`
	UploadedBy string `json:"uploaded_by,omitempty"`
}

// AppPush streams the bundle tarball into the namespace's app store.
func (c *Client) AppPush(ctx context.Context, repoID, name, version, by string, r io.Reader) (*App, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		c.BaseURL+"/api/v1/user_repo/"+repoID+"/compose-apps/"+name+"/"+version, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/gzip")
	if by != "" {
		req.Header.Set("X-Updated-By", by)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusErr("app push", resp)
	}
	var out App
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) AppList(ctx context.Context, repoID string) ([]App, error) {
	resp, err := c.do(ctx, http.MethodGet, "/api/v1/user_repo/"+repoID+"/compose-apps", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusErr("app list", resp)
	}
	var body struct {
		Apps []App `json:"apps"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return body.Apps, nil
}

func (c *Client) AppDelete(ctx context.Context, repoID, name, version string) error {
	resp, err := c.do(ctx, http.MethodDelete,
		"/api/v1/user_repo/"+repoID+"/compose-apps/"+name+"/"+version, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return statusErr("app delete", resp)
	}
	return nil
}

// ConfigFile mirrors tufd's configstore.File (subset).
type ConfigFile struct {
	Name        string   `json:"name"`
	Value       string   `json:"value"`
	OnChanged   []string `json:"on_changed,omitempty"`
	Unencrypted bool     `json:"unencrypted,omitempty"`
	UpdatedAt   int64    `json:"updated_at,omitempty"`
	UpdatedBy   string   `json:"updated_by,omitempty"`
}

// ConfigSet uploads a single config file to the namespace.
func (c *Client) ConfigSet(ctx context.Context, repoID, name string, value []byte, unencrypted bool, onChanged []string, by string) error {
	body, _ := json.Marshal(map[string]any{
		"value":       string(value),
		"on_changed":  onChanged,
		"unencrypted": unencrypted,
		"updated_by":  by,
	})
	resp, err := c.do(ctx, http.MethodPut,
		"/api/v1/user_repo/"+repoID+"/config/"+name, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return statusErr("config set", resp)
	}
	return nil
}

func (c *Client) ConfigList(ctx context.Context, repoID string) ([]ConfigFile, error) {
	resp, err := c.do(ctx, http.MethodGet, "/api/v1/user_repo/"+repoID+"/config", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusErr("config list", resp)
	}
	var body struct {
		Files []ConfigFile `json:"files"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return body.Files, nil
}

func (c *Client) ConfigDelete(ctx context.Context, repoID, name string) error {
	resp, err := c.do(ctx, http.MethodDelete, "/api/v1/user_repo/"+repoID+"/config/"+name, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return statusErr("config delete", resp)
	}
	return nil
}

// Backup streams a gzipped tar of the tufd data dir. Returns the
// body reader (caller must Close), the server-suggested filename
// (parsed from Content-Disposition), and any error. Stream is
// unbuffered — caller writes it to disk directly.
func (c *Client) Backup(ctx context.Context) (io.ReadCloser, string, error) {
	resp, err := c.do(ctx, http.MethodGet, "/api/v1/_backup", nil)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return nil, "", fmt.Errorf("api: backup status %d", resp.StatusCode)
	}
	suggested := ""
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		const prefix = `filename="`
		if i := strings.Index(cd, prefix); i >= 0 {
			rest := cd[i+len(prefix):]
			if j := strings.Index(rest, `"`); j >= 0 {
				suggested = rest[:j]
			}
		}
	}
	return resp.Body, suggested, nil
}

// RotateRoot generates a new root key for repoID, co-signs a new Root
// role at v+1 with both old and new keys, and returns the version chain.
// A 409 means the namespace has no root yet (only possible on a broken
// bootstrap); a 5xx means something failed mid-flight.
func (c *Client) RotateRoot(ctx context.Context, repoID string, req RotateRootRequest) (*RotateRootResponse, error) {
	body, _ := json.Marshal(req)
	resp, err := c.do(ctx, http.MethodPost,
		"/api/v1/user_repo/"+repoID+"/root/rotate", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return nil, statusErr("rotate root", resp)
	}
	var out RotateRootResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("api: decode rotate: %w", err)
	}
	return &out, nil
}

// UnpublishTarget removes a target entry by its name-version key (e.g.
// "lmp-42") and returns the bumped role versions. 404 means the key
// wasn't in the current Targets payload.
func (c *Client) UnpublishTarget(ctx context.Context, repoID, key string) (*PublishResponse, error) {
	resp, err := c.do(ctx, http.MethodDelete,
		"/api/v1/user_repo/"+repoID+"/targets/"+key, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusErr("unpublish target", resp)
	}
	var out PublishResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("api: decode unpublish: %w", err)
	}
	return &out, nil
}

// PublishTarget posts a new target entry and returns the resulting role
// versions. A 409 surfaces as an *Error with Status=409.
func (c *Client) PublishTarget(ctx context.Context, repoID string, req PublishRequest) (*PublishResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("api: marshal publish: %w", err)
	}
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/user_repo/"+repoID+"/targets", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return nil, statusErr("publish target", resp)
	}
	var out PublishResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("api: decode publish: %w", err)
	}
	return &out, nil
}

// FetchRoot returns the raw signed root role for a namespace and the
// x-ats-role-checksum value the server advertises.
func (c *Client) FetchRoot(ctx context.Context, repoID string) ([]byte, string, error) {
	resp, err := c.do(ctx, http.MethodGet, "/api/v1/user_repo/"+repoID+"/root.json", nil)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", statusErr("fetch root", resp)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	return b, resp.Header.Get("x-ats-role-checksum"), nil
}

// --- internals ---

func (c *Client) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Pick up the admin token from env so every caller of do()
	// inherits auth — historically PublishTarget + UnpublishTarget
	// + the wave/config helpers went out unauthenticated and only
	// the explicit OstreePush + ExportRoleKey paths set the header.
	// The server's requireAdmin gate still validates the token
	// value; this just makes sure it's PRESENT on every request.
	if tok := firstNonEmpty(os.Getenv("TUP_ADMIN_TOKEN"), os.Getenv("TUFD_ADMIN_TOKEN")); tok != "" {
		req.Header.Set("OSF-TOKEN", tok)
	}
	return c.HTTP.Do(req)
}

type Error struct {
	Op     string
	Status int
	Body   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("api %s: status=%d body=%s", e.Op, e.Status, e.Body)
}

func statusErr(op string, resp *http.Response) error {
	b, _ := io.ReadAll(resp.Body)
	return &Error{Op: op, Status: resp.StatusCode, Body: string(b)}
}
