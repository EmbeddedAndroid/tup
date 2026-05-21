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
	RepoID            string `json:"repo_id"`
	Name              string `json:"name"`
	LatestRootVersion int    `json:"latest_root_version"`
	RootKeyID         string `json:"root_keyid,omitempty"`
}

type CreateRequest struct {
	Name    string `json:"name,omitempty"`
	KeyType string `json:"key_type,omitempty"`
}

type CreateResponse struct {
	RepoID      string `json:"repo_id"`
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
