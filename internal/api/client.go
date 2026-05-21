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
	ComposeApps  map[string]string `json:"compose_apps,omitempty"`
}

// PublishResponse matches tufd's publisher.Response shape.
type PublishResponse struct {
	TargetKey        string `json:"target_key"`
	TargetsVersion   int    `json:"targets_version"`
	SnapshotVersion  int    `json:"snapshot_version"`
	TimestampVersion int    `json:"timestamp_version"`
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
