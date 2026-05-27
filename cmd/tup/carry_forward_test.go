package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/EmbeddedAndroid/tup/internal/api"
)

func TestFindLatestTargetPicksByVersion(t *testing.T) {
	doc := []byte(`{
	  "signed": {
	    "targets": {
	      "lmp-1": {
	        "length": 0,
	        "hashes": {"sha256": "aaa"},
	        "custom": {
	          "name": "lmp", "version": "1",
	          "hardwareIds": ["intel-corei7-64"],
	          "tags": ["devel"],
	          "targetFormat": "OSTREE",
	          "createdAt": "2026-05-01T00:00:00Z",
	          "docker_compose_apps": {
	            "hello": {"uri": "reg/proj/hello@sha256:0000000000000000000000000000000000000000000000000000000000000000"}
	          }
	        }
	      },
	      "lmp-7": {
	        "length": 0,
	        "hashes": {"sha256": "ggg"},
	        "custom": {
	          "name": "lmp", "version": "7",
	          "hardwareIds": ["intel-corei7-64"],
	          "tags": ["devel"],
	          "targetFormat": "OSTREE",
	          "createdAt": "2026-05-20T00:00:00Z",
	          "docker_compose_apps": {
	            "hello": {"uri": "reg/proj/hello@sha256:1111111111111111111111111111111111111111111111111111111111111111"}
	          }
	        }
	      },
	      "lmp-3-wrong-hwid": {
	        "length": 0,
	        "hashes": {"sha256": "ccc"},
	        "custom": {
	          "name": "lmp", "version": "9",
	          "hardwareIds": ["raspberrypi4"],
	          "tags": ["devel"],
	          "targetFormat": "OSTREE"
	        }
	      },
	      "binary-1": {
	        "length": 100,
	        "hashes": {"sha256": "ddd"},
	        "custom": {
	          "name": "binary", "version": "20",
	          "hardwareIds": ["intel-corei7-64"],
	          "tags": ["devel"],
	          "targetFormat": "BINARY"
	        }
	      }
	    }
	  }
	}`)
	got, err := findLatestTarget(doc, "intel-corei7-64", "devel")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected a match, got nil")
	}
	if got.sha256 != "ggg" {
		t.Errorf("wanted sha256=ggg (v7), got %s (v%d)", got.sha256, got.version)
	}
	if got.apps["hello"] != "reg/proj/hello@sha256:1111111111111111111111111111111111111111111111111111111111111111" {
		t.Errorf("wanted v7 apps, got %v", got.apps)
	}
}

func TestFindLatestTargetNoMatch(t *testing.T) {
	doc := []byte(`{"signed":{"targets":{}}}`)
	got, err := findLatestTarget(doc, "x86_64", "devel")
	if err != nil || got != nil {
		t.Errorf("expected (nil, nil), got (%v, %v)", got, err)
	}
}

func TestFindLatestTargetTieBreaksByCreatedAt(t *testing.T) {
	doc := []byte(`{
	  "signed": {
	    "targets": {
	      "lmp-5": {
	        "length": 0,
	        "hashes": {"sha256": "older"},
	        "custom": {
	          "name": "lmp", "version": "5",
	          "hardwareIds": ["intel-corei7-64"], "tags": ["devel"],
	          "targetFormat": "OSTREE",
	          "createdAt": "2026-05-01T00:00:00Z"
	        }
	      },
	      "lmp-5-redux": {
	        "length": 0,
	        "hashes": {"sha256": "newer"},
	        "custom": {
	          "name": "lmp", "version": "5",
	          "hardwareIds": ["intel-corei7-64"], "tags": ["devel"],
	          "targetFormat": "OSTREE",
	          "createdAt": "2026-05-20T00:00:00Z"
	        }
	      }
	    }
	  }
	}`)
	got, err := findLatestTarget(doc, "intel-corei7-64", "devel")
	if err != nil {
		t.Fatal(err)
	}
	if got.sha256 != "newer" {
		t.Errorf("expected createdAt tiebreaker to pick newer, got %s", got.sha256)
	}
}

func TestValidateAppPins(t *testing.T) {
	// All pinned: pass.
	ok := map[string]string{
		"a": "reg/foo@sha256:" + strings.Repeat("a", 64),
		"b": "reg/bar@sha256:" + strings.Repeat("b", 64),
	}
	if err := validateAppPins(ok); err != nil {
		t.Errorf("pinned set: %v", err)
	}
	// Empty: pass (carry-forward path).
	if err := validateAppPins(map[string]string{}); err != nil {
		t.Errorf("empty: %v", err)
	}
	// Tag-only: fail with name listed.
	bad := map[string]string{"a": "reg/foo:1"}
	err := validateAppPins(bad)
	if err == nil {
		t.Fatal("expected error for tag-only ref")
	}
	if !strings.Contains(err.Error(), "a=reg/foo:1") {
		t.Errorf("error missing offender: %v", err)
	}
	// Short digest: fail.
	short := map[string]string{"a": "reg/foo@sha256:abc"}
	if err := validateAppPins(short); err == nil {
		t.Error("expected error for short digest")
	}
}

func TestStripVersionSuffix(t *testing.T) {
	cases := map[string]string{
		"myapp-42":         "myapp",
		"lmp-base-1":       "lmp-base",
		"myapp":            "myapp",
		"myapp-foo":        "myapp-foo",
		"myapp-1.2":        "myapp-1.2", // not a bare int
	}
	for in, want := range cases {
		if got := stripVersionSuffix(in); got != want {
			t.Errorf("stripVersionSuffix(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestApplyCarryForward_YoctoPublishInheritsApps covers the gap that
// motivated splitting the carry-forward out: when the yocto agent
// publishes a new rootfs target (ostree-commit set, no -app flag) it
// must inherit the compose-apps from the latest matching target for
// the same (hwid, tag). Without this the device loses every running
// app on the next rootfs OTA.
func TestApplyCarryForward_YoctoPublishInheritsApps(t *testing.T) {
	// Mock the FetchTargets call with a targets.json that already has
	// an OSTREE target carrying compose-apps for (intel, devel).
	prior, _ := json.Marshal(map[string]any{
		"signed": map[string]any{
			"targets": map[string]any{
				"baseline-100": map[string]any{
					"length": 0,
					"hashes": map[string]string{"sha256": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"},
					"custom": map[string]any{
						"name":         "baseline",
						"version":      "100",
						"hardwareIds":  []string{"intel-corei7-64"},
						"tags":         []string{"devel"},
						"targetFormat": "OSTREE",
						"createdAt":    "2026-05-27T10:00:00Z",
						"docker_compose_apps": map[string]any{
							"tuf":   map[string]any{"uri": "reg/tuf@sha256:" + strings.Repeat("a", 64)},
							"hello": map[string]any{"uri": "reg/hello@sha256:" + strings.Repeat("b", 64)},
						},
					},
				},
			},
		},
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(prior)
	}))
	defer srv.Close()
	c := api.New(srv.URL)

	// Yocto-publish shape: ostree-commit set, no apps.
	req := api.PublishRequest{
		Name:         "intel-corei7-64",
		Version:      "200",
		TargetFormat: "OSTREE",
		SHA256:       "f00df00df00df00df00df00df00df00df00df00df00df00df00df00df00df00d",
		HardwareIDs:  []string{"intel-corei7-64"},
		Tags:         []string{"devel"},
	}
	if err := applyCarryForward(context.Background(), c, "demo", &req); err != nil {
		t.Fatal(err)
	}
	if len(req.ComposeApps) != 2 {
		t.Fatalf("expected 2 inherited apps, got %d: %+v", len(req.ComposeApps), req.ComposeApps)
	}
	if !strings.HasPrefix(req.ComposeApps["tuf"], "reg/tuf@sha256:") {
		t.Errorf("tuf app not inherited: %q", req.ComposeApps["tuf"])
	}
	// ostree-commit was supplied — must NOT be clobbered by the carry-forward.
	if !strings.HasPrefix(req.SHA256, "f00d") {
		t.Errorf("supplied SHA256 got clobbered: %s", req.SHA256)
	}
}

// TestApplyCarryForward_BothSuppliedNoFetch confirms the helper is a
// no-op (and does no HTTP) when the request is already complete.
func TestApplyCarryForward_BothSuppliedNoFetch(t *testing.T) {
	fetched := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetched = true
		w.WriteHeader(500)
	}))
	defer srv.Close()
	c := api.New(srv.URL)

	req := api.PublishRequest{
		Name: "x", Version: "1", TargetFormat: "OSTREE",
		SHA256:      "f00df00df00df00df00df00df00df00df00df00df00df00df00df00df00df00d",
		HardwareIDs: []string{"intel"},
		Tags:        []string{"devel"},
		ComposeApps: map[string]string{"a": "reg/a@sha256:" + strings.Repeat("a", 64)},
	}
	if err := applyCarryForward(context.Background(), c, "demo", &req); err != nil {
		t.Fatal(err)
	}
	if fetched {
		t.Error("applyCarryForward should not call FetchTargets when request is already complete")
	}
}
