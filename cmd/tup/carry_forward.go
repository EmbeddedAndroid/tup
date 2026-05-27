package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/EmbeddedAndroid/tup/internal/api"
)

// applyCarryForward inherits the missing piece of a publish request
// from the newest matching (project, hwid, tag) target. Symmetric:
//   - operator passed -ostree-commit but no -app → inherit apps from
//     the latest matching target (the yocto-publish case — preserves
//     a device's already-running compose-app set across a rootfs
//     rebuild, which would otherwise wipe apps to empty);
//   - operator passed -app but no -ostree-commit → inherit the
//     ostree-commit (the app-only republish case);
//   - both supplied → no inheritance, the request stands;
//   - neither supplied → fail loudly downstream.
//
// Skips when hwid or tag is empty (no key to query on), or when
// TargetFormat isn't OSTREE (BINARY/compose-only targets have their
// own lifecycle). Idempotent on a fully-supplied request.
func applyCarryForward(ctx context.Context, c *api.Client, repoID string, req *api.PublishRequest) error {
	missingSHA := req.SHA256 == ""
	missingApps := len(req.ComposeApps) == 0
	if !missingSHA && !missingApps {
		return nil
	}
	if len(req.HardwareIDs) == 0 || len(req.Tags) == 0 || req.TargetFormat != "OSTREE" {
		return nil
	}
	raw, err := c.FetchTargets(ctx, repoID)
	if err != nil {
		return fmt.Errorf("publish: carry-forward targets fetch: %w", err)
	}
	base, err := findLatestTarget(raw, req.HardwareIDs[0], req.Tags[0])
	if err != nil {
		return fmt.Errorf("publish: carry-forward parse: %w", err)
	}
	if base == nil {
		return nil
	}
	if missingSHA {
		req.SHA256 = base.sha256
		req.Length = base.length
		fmt.Fprintf(os.Stderr, "▶ inherit ostree-commit from %s-%s: %s\n",
			base.name, base.versionStr, base.sha256)
	}
	if missingApps && len(base.apps) > 0 {
		req.ComposeApps = make(map[string]string, len(base.apps))
		for k, v := range base.apps {
			req.ComposeApps[k] = v
		}
		fmt.Fprintf(os.Stderr, "▶ inherit %d compose-app(s) from %s-%s\n",
			len(base.apps), base.name, base.versionStr)
	}
	return nil
}

// targetEntry is the trimmed view of a single targets.json target we
// care about for carry-forward. We parse only the fields needed to
// (a) match (hwid, tag, OSTREE) and (b) refill a new PublishRequest.
type targetEntry struct {
	name         string
	version      int    // best-effort numeric Version (for ranking)
	versionStr   string // raw version string
	sha256       string
	length       int64
	hardwareIDs  []string
	tags         []string
	targetFormat string
	apps         map[string]string
	createdAt    time.Time
}

// targetsDoc is the minimum we parse out of targets.json. Tufd emits
// the standard ats-targets envelope; we only walk `signed.targets`.
type targetsDoc struct {
	Signed struct {
		Targets map[string]rawTarget `json:"targets"`
	} `json:"signed"`
}

type rawTarget struct {
	Length int64             `json:"length"`
	Hashes map[string]string `json:"hashes"`
	Custom *rawTargetCustom  `json:"custom,omitempty"`
}

type rawTargetCustom struct {
	Name              string                    `json:"name,omitempty"`
	Version           string                    `json:"version,omitempty"`
	HardwareIDs       []string                  `json:"hardwareIds,omitempty"`
	Tags              []string                  `json:"tags,omitempty"`
	TargetFormat      string                    `json:"targetFormat,omitempty"`
	CreatedAt         string                    `json:"createdAt,omitempty"`
	UpdatedAt         string                    `json:"updatedAt,omitempty"`
	DockerComposeApps map[string]rawComposeApp  `json:"docker_compose_apps,omitempty"`
}

type rawComposeApp struct {
	URI string `json:"uri"`
}

// findLatestTarget returns the newest target matching (hwid in
// custom.hardwareIds, tag in custom.tags, targetFormat == "OSTREE")
// or nil if no match. Ranking: higher numeric version wins; ties
// broken by later createdAt; further ties broken by lexically-larger
// name (for determinism).
func findLatestTarget(targetsJSON []byte, hwid, tag string) (*targetEntry, error) {
	var doc targetsDoc
	if err := json.Unmarshal(targetsJSON, &doc); err != nil {
		return nil, fmt.Errorf("decode targets.json: %w", err)
	}
	var best *targetEntry
	for name, t := range doc.Signed.Targets {
		if t.Custom == nil {
			continue
		}
		if t.Custom.TargetFormat != "OSTREE" {
			continue
		}
		if !sliceContains(t.Custom.HardwareIDs, hwid) {
			continue
		}
		if !sliceContains(t.Custom.Tags, tag) {
			continue
		}
		e := &targetEntry{
			name:         t.Custom.Name,
			versionStr:   t.Custom.Version,
			sha256:       t.Hashes["sha256"],
			length:       t.Length,
			hardwareIDs:  append([]string(nil), t.Custom.HardwareIDs...),
			tags:         append([]string(nil), t.Custom.Tags...),
			targetFormat: t.Custom.TargetFormat,
		}
		if e.name == "" {
			// Fall back to the targets-map key when custom.name is empty
			// (some legacy targets omitted it). Strip trailing `-<ver>`
			// suffix to recover the bare name.
			e.name = stripVersionSuffix(name)
		}
		if v, err := strconv.Atoi(t.Custom.Version); err == nil {
			e.version = v
		}
		if t.Custom.CreatedAt != "" {
			if ct, err := time.Parse(time.RFC3339Nano, t.Custom.CreatedAt); err == nil {
				e.createdAt = ct
			}
		}
		if t.Custom.DockerComposeApps != nil {
			e.apps = make(map[string]string, len(t.Custom.DockerComposeApps))
			for k, v := range t.Custom.DockerComposeApps {
				e.apps[k] = v.URI
			}
		}
		if best == nil || isNewer(e, best) {
			best = e
		}
	}
	return best, nil
}

// isNewer ranks targets by numeric version, then createdAt, then name.
func isNewer(a, b *targetEntry) bool {
	if a.version != b.version {
		return a.version > b.version
	}
	if !a.createdAt.Equal(b.createdAt) {
		return a.createdAt.After(b.createdAt)
	}
	return a.name > b.name
}

func sliceContains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// stripVersionSuffix turns "myapp-42" into "myapp". Lossy for names
// that legitimately end in -<digits>; only used as a fallback when
// custom.name is empty.
func stripVersionSuffix(s string) string {
	if i := strings.LastIndex(s, "-"); i > 0 {
		tail := s[i+1:]
		if _, err := strconv.Atoi(tail); err == nil {
			return s[:i]
		}
	}
	return s
}

// digestPinned matches @sha256:<64 lowercase hex> as a substring.
// composectl/aktualizr require this on every -app value; we surface
// a clear error at publish time rather than letting it die on-device.
var digestPinned = regexp.MustCompile(`@sha256:[0-9a-f]{64}`)

// validateAppPins returns an error if any app URI is missing a
// @sha256:<digest> pin. Empty map is allowed (the publish may be
// ostree-only and inherit apps from the latest matching target).
func validateAppPins(apps map[string]string) error {
	var unpinned []string
	for name, uri := range apps {
		if !digestPinned.MatchString(uri) {
			unpinned = append(unpinned, fmt.Sprintf("%s=%s", name, uri))
		}
	}
	if len(unpinned) > 0 {
		return fmt.Errorf("app refs must be digest-pinned (composectl rejects tag refs); unpinned: %s",
			strings.Join(unpinned, ", "))
	}
	return nil
}
