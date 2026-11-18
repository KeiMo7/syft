package diff

import (
	"regexp"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// numericPrefix captures a dotted numeric component of an unparseable version string such
// as "1.2.3-rc1". A single bare number is deliberately not accepted: date-style versions
// like "20240101" would otherwise look like a major version and produce fake upgrades.
var numericPrefix = regexp.MustCompile(`\d+\.\d+(?:\.\d+)*`)

// compareVersions classifies the movement between two non-empty version strings.
//
// Parsing is attempted in order on the raw value, then with a leading epoch ("1:2.3.4")
// and leading "v" stripped, then on the first numeric dotted prefix. Values that still
// cannot be parsed as semantic versions are returned as uncomparable rather than guessed
// at, so a downgrade can never be reported from an alphabetic sort of date-based or
// distro-specific version schemes.
func compareVersions(oldVersion, newVersion string) VersionChangeDirection {
	oldSemver, oldOK := parseVersion(oldVersion)
	newSemver, newOK := parseVersion(newVersion)

	if !oldOK || !newOK {
		return NoDirection
	}

	switch {
	case newSemver.GreaterThan(oldSemver):
		if oldSemver.Major() == newSemver.Major() &&
			oldSemver.Minor() == newSemver.Minor() &&
			oldSemver.Prerelease() == "" && newSemver.Prerelease() == "" {
			return RevisionOnly
		}
		return Upgrade
	case newSemver.LessThan(oldSemver):
		return Downgrade
	default:
		// equal core version but different strings (e.g. pre-release/build metadata);
		// treat as a revision-level movement rather than identical
		if oldVersion == newVersion {
			return NoDirection
		}
		return RevisionOnly
	}
}

func parseVersion(raw string) (*semver.Version, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, false
	}

	for index, candidate := range versionCandidates(raw) {
		if index == 0 && !strings.Contains(candidate, ".") {
			// a bare number is almost always a date or a build identifier (e.g. "20240101"),
			// not a semantic version; skip straight to the dotted-prefix salvage pass
			continue
		}
		if parsed, err := semver.NewVersion(candidate); err == nil && parsed != nil {
			return parsed, true
		}
	}

	return nil, false
}

// versionCandidates produces progressively more aggressive normalizations of a version
// string so that common distro/OS conventions (epochs, leading v, trailing suffixes) can
// still be compared without accepting arbitrary text as a version.
func versionCandidates(raw string) []string {
	candidates := []string{raw}

	if idx := strings.Index(raw, ":"); idx >= 0 {
		candidates = append(candidates, raw[idx+1:])
	}

	stripped := strings.TrimPrefix(strings.TrimPrefix(raw, "v"), "V")
	if stripped != raw {
		candidates = append(candidates, stripped)
	}

	if match := numericPrefix.FindString(raw); match != "" && match != raw {
		candidates = append(candidates, match)
	}

	return candidates
}
