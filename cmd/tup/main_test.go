package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/foundriesio/tup/internal/api"
)

func TestLoadManifest_AllFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "build-98.json")
	body := `{
		"sha256": "deadbeef",
		"length": 0,
		"target_format": "OSTREE",
		"hardware_ids": ["intel-corei7-64"],
		"tags": ["main"],
		"uri": "https://ostree.acme/repo",
		"orig_uri": "https://api.foundries.io/projects/acme/lmp/builds/98",
		"image_file": "lmp-base-console-image.wic.gz",
		"compose_apps": {"web": "ghcr.io/acme/web@sha256:abc"},
		"lmp_ver": "98",
		"lmp_manifest_sha": "aaa",
		"meta_subscriber_overrides_sha": "bbb",
		"containers_sha": "ccc"
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := loadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if m.SHA256 != "deadbeef" {
		t.Errorf("SHA256 = %q", m.SHA256)
	}
	if m.LMPVer != "98" || m.LMPManifestSHA != "aaa" || m.ContainersSHA != "ccc" {
		t.Errorf("LmP fields not parsed: %+v", m)
	}
	if len(m.HardwareIDs) != 1 || m.HardwareIDs[0] != "intel-corei7-64" {
		t.Errorf("HardwareIDs = %v", m.HardwareIDs)
	}
	if m.ComposeApps["web"] != "ghcr.io/acme/web@sha256:abc" {
		t.Errorf("ComposeApps = %v", m.ComposeApps)
	}
}

// TestMergeManifest_FlagsWin: the manifest sets sha+lmp-ver, then a
// flag-style override on dst replaces them (caller is expected to do this
// post-merge). Locks in the precedence rule documented in -h.
func TestMergeManifest_FlagsWin(t *testing.T) {
	// Simulate: manifest seeded dst, then flag overrides.
	dst := api.PublishRequest{Name: "lmp", Version: "42"}
	src := &api.PublishRequest{
		SHA256: "old", LMPVer: "old-ver", URI: "old-uri",
	}
	mergeManifest(&dst, src)
	if dst.SHA256 != "old" || dst.LMPVer != "old-ver" {
		t.Fatalf("manifest didn't seed dst: %+v", dst)
	}
	// Caller layer: explicit -sha256 + -lmp-ver flags assign over the top.
	dst.SHA256 = "new"
	dst.LMPVer = "new-ver"
	if dst.SHA256 != "new" || dst.LMPVer != "new-ver" {
		t.Fatal("explicit overrides should win")
	}
	// URI was set by manifest and never overridden — must remain.
	if dst.URI != "old-uri" {
		t.Errorf("URI = %q, want preserved from manifest", dst.URI)
	}
}

// TestMergeManifest_EmptyFieldsDoNotOverwrite: a manifest with missing
// LMPVer must not zero out an existing one. Guards against the merge being
// dumb-copy rather than copy-if-set.
func TestMergeManifest_EmptyFieldsDoNotOverwrite(t *testing.T) {
	dst := api.PublishRequest{LMPVer: "preexisting"}
	src := &api.PublishRequest{SHA256: "x"} // no LMPVer
	mergeManifest(&dst, src)
	if dst.LMPVer != "preexisting" {
		t.Fatalf("empty src.LMPVer overwrote dst: %q", dst.LMPVer)
	}
	if dst.SHA256 != "x" {
		t.Fatalf("SHA256 should have been merged in: %q", dst.SHA256)
	}
}
