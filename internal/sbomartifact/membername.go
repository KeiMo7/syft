package sbomartifact

import (
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/sbom"
)

// IndexName is the fixed, reserved name of the index document inside directory and archive targets.
const IndexName = "index.json"

// memberExtension maps a format id to the suffix used for its on-disk documents. Formats without a
// registered extension fall back to a generic .txt so that table/text style encoders still land in
// a readable, distinct member.
var memberExtension = map[sbom.FormatID]string{
	"syft-json":      ".syft.json",
	"spdx-json":      ".spdx.json",
	"cyclonedx-json": ".cdx.json",
	"cyclonedx-xml":  ".cdx.xml",
	"spdx-tag-value": ".spdx.tv",
	"github-json":    ".github.json",
	"syft-table":     ".table.txt",
	"syft-text":      ".text.txt",
	"template":       ".template.txt",
	"purls":          ".purl.txt",
}

var unsafeMemberChars = regexp.MustCompile(`[^a-z0-9._-]+`)

// MemberName deterministically derives the on-disk member name for an encoded document from its
// format id and version. The same encoder always produces the same name across runs and across the
// directory and archive forms, so two writes of one manifest have identical member sets.
//
// Examples:
//
//	syft-json (no version)          -> syft-json.syft.json
//	spdx-json @ 2.3                 -> spdx-json-2.3.spdx.json
//	cyclonedx-json @ 1.5            -> cyclonedx-json-1.5.cdx.json
func MemberName(enc sbom.FormatEncoder) string {
	base := sanitizeName(string(enc.ID()))
	if v := enc.Version(); v != "" && v != sbom.AnyVersion {
		base += "-" + sanitizeName(v)
	}
	return base + extensionFor(enc.ID())
}

func extensionFor(id sbom.FormatID) string {
	if ext, ok := memberExtension[id]; ok {
		return ext
	}
	return "." + sanitizeName(string(id)) + ".txt"
}

// sanitizeName collapses any character that is not safe for a cross-platform file name into a
// single hyphen and trims leading/trailing hyphens so derived names stay stable and collision-free
// for the format ids and version strings syft actually emits.
func sanitizeName(s string) string {
	s = strings.ToLower(s)
	s = unsafeMemberChars.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "unknown"
	}
	return s
}
