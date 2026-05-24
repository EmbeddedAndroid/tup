package main

import (
	"strings"
	"testing"
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
