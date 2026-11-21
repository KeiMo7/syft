// Package timeline records successive SBOM generations as an append-only journal and derives a
// change timeline from it.
//
// The timeline is a side channel: it never alters the SBOM that a scan produces, and it is only
// written when a history directory is explicitly configured. Each generation appends one
// self-contained snapshot record. The timeline itself (first appearance, version changes, source
// changes, removal) is derived from those snapshots, so appending the same history in a different
// order yields the same timeline.
//
// Component identity is defined in exactly one place (Component.Key). The same key is used to
// deduplicate a snapshot, to deduplicate imported records, and to compute transitions between
// snapshots.
package timeline

import (
	"net/url"
	"sort"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

// Component is one package as it appears at one point in the timeline. Key is the stable
// identity; Version and Source are the attributes whose changes are reported.
type Component struct {
	// Key is the identity of the component. It is derived from the purl (type, namespace, name)
	// when available and from the syft package type and name otherwise. Version and Source are
	// deliberately not part of the key: a version bump or a repository change is a change of an
	// existing component, not a removal followed by an addition.
	Key string `json:"key"`

	// Name is the normalized component name (from the purl when available).
	Name string `json:"name"`

	// Type is the ecosystem of the component (the purl type when available).
	Type string `json:"type"`

	// Namespace is the purl namespace, when present.
	Namespace string `json:"namespace,omitempty"`

	// Version is the version recorded at this point.
	Version string `json:"version,omitempty"`

	// PURL is the package URL as recorded by the generating scan, when present.
	PURL string `json:"purl,omitempty"`

	// Source is the repository or registry the package came from, normalized to a single string.
	// It is populated from cataloger metadata where available and from well-known purl
	// qualifiers otherwise. An empty value means the source is unknown, not that it is absent.
	Source string `json:"source,omitempty"`
}

// IdentityKey returns the component identity for the given package. It is the only place where
// component identity is derived; everything that compares or deduplicates components uses it.
func IdentityKey(p pkg.Package) (key, componentType, namespace, name string) {
	componentType = strings.ToLower(string(p.Type))
	name = p.Name

	if p.PURL != "" {
		if u, err := packageurl.FromString(p.PURL); err == nil {
			if err := u.Normalize(); err == nil {
				componentType = u.Type
				namespace = u.Namespace
				name = u.Name
			}
		}
	}

	if namespace != "" {
		key = componentType + "/" + namespace + "/" + name
	} else {
		key = componentType + "/" + name
	}

	return key, componentType, namespace, name
}

// ComponentFromPackage builds the timeline representation of a package.
func ComponentFromPackage(p pkg.Package) Component {
	key, componentType, namespace, name := IdentityKey(p)
	return Component{
		Key:       key,
		Name:      name,
		Type:      componentType,
		Namespace: namespace,
		Version:   p.Version,
		PURL:      p.PURL,
		Source:    SourceOf(p),
	}
}

// ComponentsFromSBOM extracts the deduplicated component set of an SBOM, sorted by key.
//
// If several packages share an identity key (for example the same package found in two
// locations), one representative is kept deterministically: the entry with the smallest
// (version, source, purl) tuple. The timeline models one state per component, so this is the
// only lossless-enough choice that keeps comparisons independent of catalog order.
func ComponentsFromSBOM(s sbom.SBOM) []Component {
	if s.Artifacts.Packages == nil {
		return nil
	}

	byKey := make(map[string]Component)
	for _, p := range s.Artifacts.Packages.Sorted() {
		if p.Name == "" {
			continue
		}
		c := ComponentFromPackage(p)
		if existing, ok := byKey[c.Key]; !ok || componentLess(c, existing) {
			byKey[c.Key] = c
		}
	}

	components := make([]Component, 0, len(byKey))
	for _, c := range byKey {
		components = append(components, c)
	}
	sort.Slice(components, func(i, j int) bool {
		return components[i].Key < components[j].Key
	})
	return components
}

func componentLess(a, b Component) bool {
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	return a.PURL < b.PURL
}

// SourceOf returns the repository or registry a package came from. The value is intentionally a
// single opaque string: it is compared for equality only, and the timeline reports it verbatim
// when it changes.
func SourceOf(p pkg.Package) string {
	if source := sourceFromMetadata(p.Metadata); source != "" {
		return normalizeSource(source)
	}
	return sourceFromPURL(p.PURL)
}

func sourceFromMetadata(metadata any) string {
	switch m := metadata.(type) {
	case pkg.RustCargoLockEntry:
		return m.Source
	case pkg.RustBinaryAuditEntry:
		return m.Source
	case pkg.DartPubspecLockEntry:
		if m.HostedURL != "" {
			return m.HostedURL
		}
		return m.VcsURL
	case pkg.PhpComposerLockEntry:
		return m.Source.URL
	case pkg.PhpComposerInstalledEntry:
		return m.Source.URL
	case pkg.NpmPackageLockEntry:
		return m.Resolved
	case pkg.YarnLockEntry:
		return m.Resolved
	case pkg.NpmPackage:
		return m.URL
	case pkg.PythonPackage:
		if m.DirectURLOrigin != nil {
			return m.DirectURLOrigin.URL
		}
	case pkg.PythonRequirementsEntry:
		return m.URL
	case pkg.RDescription:
		return m.Repository
	case pkg.VcpkgManifest:
		if m.Registry != nil {
			return m.Registry.Repository
		}
	case pkg.ELFBinaryPackageNoteJSONPayload:
		return m.SourceRepo
	case pkg.CondaMetaPackage:
		return m.Channel
	case pkg.JavaVMInstallation:
		if m.Release.SourceRepo != "" {
			return m.Release.SourceRepo
		}
		return m.Release.BuildSourceRepo
	case pkg.TerraformLockProviderEntry:
		return m.URL
	case pkg.DenoRemoteLockEntry:
		return m.URL
	case pkg.HackageStackYamlLockEntry:
		return m.SnapshotURL
	case pkg.LuaRocksPackage:
		return m.URL
	case pkg.OpamPackage:
		return m.URL
	}
	return ""
}

var sourcePURLQualifiers = []string{
	"repository_url",
	"vcs_url",
	"hosted_url",
}

func sourceFromPURL(purl string) string {
	if purl == "" {
		return ""
	}
	u, err := packageurl.FromString(purl)
	if err != nil {
		return ""
	}
	qualifiers := u.Qualifiers.Map()
	for _, key := range sourcePURLQualifiers {
		if value := qualifiers[key]; value != "" {
			return normalizeSource(value)
		}
	}
	if value := qualifiers["download_url"]; value != "" {
		return normalizeArtifactURL(value)
	}
	return ""
}

// artifactExtensions are the suffixes of files that identify one artifact inside a repository
// rather than a repository. A source recorded as such a URL is reduced to the repository it lives
// in, so a version bump does not look like the package switched repositories.
var artifactExtensions = []string{
	".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".zip", ".whl", ".egg",
	".jar", ".war", ".crate", ".gem", ".nupkg", ".apk", ".deb", ".rpm",
	".gz", ".bz2", ".xz",
}

func normalizeSource(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return ""
	}

	// a VCS prefix ("git+https://...") names the transport, not the repository, and a VCS URL
	// carries the pinned revision after an "@"; neither distinguishes the repository
	if scheme, rest, ok := strings.Cut(source, "+"); ok && isVCSPrefix(scheme) {
		source = stripVCSRevision(rest)
	}

	source = strings.TrimSuffix(source, "/")
	if looksLikeArtifactURL(source) {
		return repositoryOf(source)
	}
	return source
}

func stripVCSRevision(source string) string {
	// only the final path segment can hold "@<ref>"; anything before it is authority/userinfo
	slash := strings.LastIndex(source, "/")
	if slash < 0 {
		return source
	}
	if at := strings.LastIndex(source[slash:], "@"); at >= 0 {
		return source[:slash+at]
	}
	return source
}

func isVCSPrefix(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "git", "hg", "svn", "bzr":
		return true
	}
	return false
}

func looksLikeArtifactURL(source string) bool {
	lower := strings.ToLower(source)
	for _, ext := range artifactExtensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func normalizeArtifactURL(source string) string {
	return repositoryOf(normalizeSource(source))
}

// repositoryOf reduces an artifact URL to the registry that hosts it.
func repositoryOf(source string) string {
	u, err := url.Parse(source)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return source
	}
	return u.Scheme + "://" + u.Host
}
