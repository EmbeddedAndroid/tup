package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListNamespaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/user_repo" || r.Method != http.MethodGet {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"factories": []Factory{
				{RepoID: "rid-1", Name: "alpha", LatestRootVersion: 1, RootKeyID: "k1"},
				{RepoID: "rid-2", Name: "beta", LatestRootVersion: 2, RootKeyID: "k2"},
			},
		})
	}))
	defer srv.Close()

	got, err := New(srv.URL).ListNamespaces(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "alpha" || got[1].Name != "beta" {
		t.Fatalf("got %+v", got)
	}
}

func TestCreateNamespace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/user_repo" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		var req CreateRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Name != "acme" {
			t.Errorf("name = %q", req.Name)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(CreateResponse{
			RepoID: "rid-new", Name: "acme", RootKeyID: "k0", RootVersion: 1,
		})
	}))
	defer srv.Close()

	got, err := New(srv.URL).CreateNamespace(context.Background(), CreateRequest{Name: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if got.RepoID != "rid-new" || got.RootVersion != 1 {
		t.Fatalf("got %+v", got)
	}
}

func TestFetchRoot(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/user_repo/") {
			t.Errorf("path %s", r.URL.Path)
		}
		w.Header().Set("x-ats-role-checksum", "checksum-xyz")
		_, _ = w.Write([]byte(`{"signatures":[],"signed":{"_type":"Root","version":1}}`))
	}))
	defer srv.Close()

	body, sum, err := New(srv.URL).FetchRoot(context.Background(), "rid-1")
	if err != nil {
		t.Fatal(err)
	}
	if sum != "checksum-xyz" {
		t.Fatalf("checksum = %q", sum)
	}
	if !strings.Contains(string(body), "_type") {
		t.Fatalf("body missing _type: %s", body)
	}
}

func TestPublishTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/v1/user_repo/rid-1/targets" {
			t.Errorf("path = %s", r.URL.Path)
		}
		var got PublishRequest
		_ = json.NewDecoder(r.Body).Decode(&got)
		if got.Name != "lmp" || got.Version != "42" || got.SHA256 != "abc" {
			t.Errorf("body decoded as %+v", got)
		}
		if len(got.HardwareIDs) != 1 || got.HardwareIDs[0] != "intel-corei7-64" {
			t.Errorf("HardwareIDs = %v", got.HardwareIDs)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(PublishResponse{
			TargetKey: "lmp-42", TargetsVersion: 2, SnapshotVersion: 2, TimestampVersion: 2000,
		})
	}))
	defer srv.Close()

	got, err := New(srv.URL).PublishTarget(context.Background(), "rid-1", PublishRequest{
		Name: "lmp", Version: "42", SHA256: "abc",
		HardwareIDs: []string{"intel-corei7-64"}, Tags: []string{"main"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.TargetKey != "lmp-42" || got.TargetsVersion != 2 || got.TimestampVersion != 2000 {
		t.Fatalf("got %+v", got)
	}
}

// TestPublishTarget_SendsLmPFields confirms the new LmP fields land in
// the JSON body that hits tufd. tup is a thin client — if it drops a
// field on the way out, the wire artifact is missing it forever.
func TestPublishTarget_SendsLmPFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got PublishRequest
		_ = json.NewDecoder(r.Body).Decode(&got)
		if got.LMPVer != "98" || got.LMPManifestSHA != "aaa" ||
			got.MetaSubscriberOverridesSHA != "bbb" || got.ContainersSHA != "ccc" {
			t.Errorf("LmP fields missing in body: %+v", got)
		}
		if got.OrigURI != "https://api.foundries.io/x" || got.ImageFile != "lmp.wic.gz" {
			t.Errorf("orig_uri/image_file missing: orig=%q file=%q", got.OrigURI, got.ImageFile)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(PublishResponse{
			TargetKey: "lmp-98", TargetsVersion: 2, SnapshotVersion: 2, TimestampVersion: 2000,
		})
	}))
	defer srv.Close()

	_, err := New(srv.URL).PublishTarget(context.Background(), "rid-1", PublishRequest{
		Name: "lmp", Version: "98", SHA256: "deadbeef",
		OrigURI: "https://api.foundries.io/x",
		ImageFile: "lmp.wic.gz",
		LMPVer: "98", LMPManifestSHA: "aaa",
		MetaSubscriberOverridesSHA: "bbb", ContainersSHA: "ccc",
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestPublishTarget_Conflict guards the duplicate-publish path: a 409 from
// tufd must surface as an *Error so callers can branch on it.
func TestPublishTarget_Conflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"target already exists","key":"lmp-42"}`))
	}))
	defer srv.Close()

	_, err := New(srv.URL).PublishTarget(context.Background(), "rid-1", PublishRequest{
		Name: "lmp", Version: "42", SHA256: "abc",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *Error
	if !errorsAs(err, &apiErr) {
		t.Fatalf("expected *Error, got %T", err)
	}
	if apiErr.Status != http.StatusConflict {
		t.Fatalf("status = %d, want 409", apiErr.Status)
	}
}

func TestRotateRoot(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/api/v1/user_repo/rid-1/root/rotate" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(RotateRootResponse{
			NewRootVersion:   2,
			NewRootKeyID:     "newkey",
			PriorRootKeyID:   "oldkey",
			PriorRootVersion: 1,
		})
	}))
	defer srv.Close()

	got, err := New(srv.URL).RotateRoot(context.Background(), "rid-1", RotateRootRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got.NewRootVersion != 2 || got.PriorRootKeyID != "oldkey" {
		t.Fatalf("got %+v", got)
	}
}

func TestStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := New(srv.URL).ListNamespaces(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var apiErr *Error
	if !errorsAs(err, &apiErr) {
		t.Fatalf("expected *Error, got %T", err)
	}
	if apiErr.Status != http.StatusInternalServerError {
		t.Fatalf("status = %d", apiErr.Status)
	}
}

func errorsAs(err error, target any) bool {
	type as interface {
		As(any) bool
	}
	_ = err
	_ = target
	// stdlib has errors.As but importing it just for this is overkill;
	// inline check is sufficient for the test.
	if e, ok := target.(**Error); ok {
		if v, ok := err.(*Error); ok {
			*e = v
			return true
		}
	}
	return false
}
