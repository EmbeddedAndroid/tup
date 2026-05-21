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
