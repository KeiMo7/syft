package diff

import (
	"strings"

	packageurl "github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/pkg"
)

// identity captures the deterministic matching identity of a package.
//
// The primary rule is the Package URL: PURLs are globally unique namespaces for a
// component (ecosystem + namespace + name + distribution qualifiers), so two packages
// whose PURLs are equal after normalization and version stripping describe the same
// component even across releases. When a package carries no PURL (or an invalid one),
// matching degrades to package type + name; if the type is empty as well, the name alone
// is used. Every degraded match is marked unreliable on the resulting Change.
type identity struct {
	key  string
	rule IdentityRule
	purl string
}

func componentIdentity(p pkg.Package) identity {
	if p.PURL != "" {
		if key, ok := purlIdentityKey(p.PURL); ok {
			return identity{key: key, rule: PURLIdentity, purl: p.PURL}
		}
	}

	if p.Type != "" && p.Type != pkg.UnknownPkg {
		return identity{
			key:  "name+type:" + string(p.Type) + ":" + p.Name,
			rule: NameTypeIdentity,
			purl: p.PURL,
		}
	}

	return identity{
		key:  "name:" + p.Name,
		rule: NameIdentity,
		purl: p.PURL,
	}
}

// purlIdentityKey normalizes a PURL and drops the version so the key identifies the
// component across releases. Distribution qualifiers (e.g. arch, distro, repository_url)
// are retained because the same name from a different distribution is not the same
// component. The subpath is dropped: it points inside the package rather than at it.
func purlIdentityKey(rawPURL string) (string, bool) {
	parsed, err := packageurl.FromString(rawPURL)
	if err != nil {
		return "", false
	}

	parsed.Version = ""
	parsed.Subpath = ""

	key := strings.TrimSpace(parsed.String())
	if key == "" || parsed.Name == "" {
		return "", false
	}

	return "purl:" + key, true
}

// degraded reports whether this identity was produced by a fallback rule rather than the
// primary PURL rule.
func (i identity) degraded() bool {
	return i.rule != PURLIdentity
}
