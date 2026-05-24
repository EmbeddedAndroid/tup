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
				{ProjectID: "rid-1", Name: "alpha", LatestRootVersion: 1, RootKeyID: "k1"},
				{ProjectID: "rid-2", Name: "beta", LatestRootVersion: 2, RootKeyID: "k2"},
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
			ProjectID: "rid-new", Name: "acme", RootKeyID: "k0", RootVersion: 1,
		})
	}))
	defer srv.Close()

	got, err := New(srv.URL).CreateNamespace(context.Background(), CreateRequest{Name: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if got.ProjectID != "rid-new" || got.RootVersion != 1 {
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

func TestStageRotation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/user_repo/demo/root/stage" {
			t.Errorf("path = %s", r.URL.Path)
		}
		var req StageRotationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.NewPublicKeyPEM == "" {
			t.Error("new_pubkey_pem empty")
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(StageRotationResponse{
			StagingID:      "abc123",
			NewRootVersion: 2,
			NewRootKeyID:   "newkey",
			PriorRootKeyID: "oldkey",
			BytesToSign:    []byte(`{"_type":"Root","version":2}`),
			RequiredKeyIDs: []string{"oldkey", "newkey"},
		})
	}))
	defer srv.Close()

	got, err := New(srv.URL).StageRotation(context.Background(), "demo", StageRotationRequest{
		NewPublicKeyPEM: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.StagingID != "abc123" || got.NewRootVersion != 2 || len(got.RequiredKeyIDs) != 2 {
		t.Fatalf("got %+v", got)
	}
}

func TestFinalizeRotation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/user_repo/demo/root/finalize" {
			t.Errorf("path = %s", r.URL.Path)
		}
		var req FinalizeRotationRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.StagingID == "" || len(req.Envelope) == 0 {
			t.Error("staging_id or envelope missing")
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(RotateRootResponse{
			NewRootVersion: 2, NewRootKeyID: "newkey",
			PriorRootKeyID: "oldkey", PriorRootVersion: 1,
		})
	}))
	defer srv.Close()

	got, err := New(srv.URL).FinalizeRotation(context.Background(), "demo", FinalizeRotationRequest{
		StagingID: "abc123",
		Envelope:  []byte(`{"signatures":[],"signed":"abc"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.NewRootVersion != 2 {
		t.Fatalf("got %+v", got)
	}
}

func TestBootstrapStage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/user_repo/_bootstrap-stage" {
			t.Errorf("path = %s", r.URL.Path)
		}
		var req BootstrapStageRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Name != "acme" || req.RootPublicKeyPEM == "" {
			t.Errorf("body = %+v", req)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(BootstrapStageResponse{
			StagingID: "stage1", ProjectID: "rid-1", Name: "acme",
			RootKeyID: "rootK", TargetsKeyID: "tK",
			SnapshotKeyID: "sK", TimestampKeyID: "tsK",
			BytesToSign:    []byte(`{"_type":"Root","version":1}`),
			RequiredKeyIDs: []string{"rootK"},
		})
	}))
	defer srv.Close()

	got, err := New(srv.URL).BootstrapStage(context.Background(), BootstrapStageRequest{
		Name:             "acme",
		RootPublicKeyPEM: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.StagingID != "stage1" || got.ProjectID != "rid-1" || got.RootKeyID != "rootK" {
		t.Fatalf("got %+v", got)
	}
}

func TestBootstrapFinalize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/user_repo/_bootstrap-finalize" {
			t.Errorf("path = %s", r.URL.Path)
		}
		var req BootstrapFinalizeRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.StagingID == "" || len(req.Envelope) == 0 {
			t.Error("missing fields")
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(CreateResponse{
			ProjectID: "rid-1", Name: "acme",
			RootKeyID: "rootK", RootVersion: 1,
		})
	}))
	defer srv.Close()

	got, err := New(srv.URL).BootstrapFinalize(context.Background(), BootstrapFinalizeRequest{
		StagingID: "stage1",
		Envelope:  []byte(`{"signatures":[],"signed":""}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ProjectID != "rid-1" || got.RootVersion != 1 {
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

// TestClientDo_SetsOSFTokenFromEnv is the regression test for the
// missing-auth bug that caused tup publish to land unauthenticated
// at tufd's /api/v1/user_repo/<rid>/publish endpoint while the
// dedicated ostree push path worked. do() now picks up the admin
// token from env so EVERY API call inherits auth without each
// helper having to remember.
func TestClientDo_SetsOSFTokenFromEnv(t *testing.T) {
	t.Setenv("TUP_ADMIN_TOKEN", "secret-tok-abc")

	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("OSF-TOKEN")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"target_key":"k","targets_version":1,"snapshot_version":1,"timestamp_version":1}`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, err := c.PublishTarget(context.Background(), "demo", PublishRequest{
		Name: "img", Version: "1", TargetFormat: "OSTREE", SHA256: "deadbeef",
	})
	if err != nil {
		t.Fatalf("PublishTarget: %v", err)
	}
	if gotHeader != "secret-tok-abc" {
		t.Errorf("OSF-TOKEN not forwarded: got %q want secret-tok-abc", gotHeader)
	}
}

// TestClientDo_TufdTokenFallback covers the second env var name we
// recognize (TUFD_ADMIN_TOKEN). Operators sometimes export the
// server-side env name; tup should honor it as a fallback.
func TestClientDo_TufdTokenFallback(t *testing.T) {
	t.Setenv("TUP_ADMIN_TOKEN", "")
	t.Setenv("TUFD_ADMIN_TOKEN", "fallback-token")

	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("OSF-TOKEN")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"target_key":"k","targets_version":1,"snapshot_version":1,"timestamp_version":1}`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	_, _ = c.PublishTarget(context.Background(), "demo", PublishRequest{
		Name: "img", Version: "1", TargetFormat: "OSTREE", SHA256: "deadbeef",
	})
	if gotHeader != "fallback-token" {
		t.Errorf("TUFD_ADMIN_TOKEN fallback lost: got %q", gotHeader)
	}
}

// TestNew_PicksUpAdminTokenFromEnv closes task #67. Pre-fix the
// admin token had to be plumbed as a parameter to every helper that
// wrote its own *http.Request (OstreeInit, OstreePutObject, etc.),
// which led to silent 401s when a helper forgot the Set("OSF-TOKEN",
// ...) line. The constructor now reads the env once + the Client
// uses it on every request.
func TestNew_PicksUpAdminTokenFromEnv(t *testing.T) {
	t.Run("TUP_ADMIN_TOKEN preferred", func(t *testing.T) {
		t.Setenv("TUP_ADMIN_TOKEN", "tup-token")
		t.Setenv("TUFD_ADMIN_TOKEN", "tufd-token")
		c := New("http://x")
		if c.AdminToken != "tup-token" {
			t.Errorf("AdminToken = %q, want tup-token (TUP_ADMIN_TOKEN takes precedence)", c.AdminToken)
		}
	})
	t.Run("TUFD_ADMIN_TOKEN fallback", func(t *testing.T) {
		t.Setenv("TUP_ADMIN_TOKEN", "")
		t.Setenv("TUFD_ADMIN_TOKEN", "fallback-token")
		c := New("http://x")
		if c.AdminToken != "fallback-token" {
			t.Errorf("AdminToken = %q, want fallback-token", c.AdminToken)
		}
	})
	t.Run("neither set → empty", func(t *testing.T) {
		t.Setenv("TUP_ADMIN_TOKEN", "")
		t.Setenv("TUFD_ADMIN_TOKEN", "")
		c := New("http://x")
		if c.AdminToken != "" {
			t.Errorf("AdminToken = %q, want empty", c.AdminToken)
		}
	})
}

// TestClient_SetsOsfTokenOnAllPaths walks every code path that
// builds its own *http.Request (not via do()) and asserts the
// OSF-TOKEN header is present. Pre-#67 each path set the header
// itself; if any path forgot, requests went out unauthenticated
// + the server's requireAdmin returned 401.
func TestClient_SetsOsfTokenOnAllPaths(t *testing.T) {
	t.Setenv("TUP_ADMIN_TOKEN", "header-canary")
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("OSF-TOKEN"))
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/init") {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	c := New(srv.URL)

	ctx := context.Background()
	_ = c.OstreeInit(ctx, "rid-1", "")
	_ = c.OstreeHasObject(ctx, "rid-1", "ab", "cdef.commit", "")
	_, _ = c.OstreePutObject(ctx, "rid-1", "ab", "cdef.commit", "", strings.NewReader("x"), 1)
	_ = c.OstreePutRef(ctx, "rid-1", "main", "deadbeef", "")

	for i, got := range seen {
		if got != "header-canary" {
			t.Errorf("request %d: OSF-TOKEN = %q, want header-canary", i, got)
		}
	}
	if len(seen) != 4 {
		t.Errorf("got %d requests, want 4", len(seen))
	}
}
