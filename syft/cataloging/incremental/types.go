package incremental

import (
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

type artifactID = artifact.ID
type artifactRelationship = artifact.Relationship
type identifiable = artifact.Identifiable
type packageLister = *pkg.Collection
type pkgPackage = pkg.Package
type artifactMaps = sbom.Artifacts

func pkgCollection() *pkg.Collection {
	return pkg.NewCollection()
}
