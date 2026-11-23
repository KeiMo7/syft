// Package identitymerge applies the identity engine to an SBOM. It lives outside syft/pkg/identity
// so the engine stays free of SBOM model dependencies (and so the SBOM can carry the merge report
// without an import cycle).
package identitymerge

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/identity"
	"github.com/anchore/syft/syft/sbom"
)

// MergeSBOM folds the packages of the given SBOM by identity. The SBOM is modified in place: the
// package collection holds one entry per component identity, relationships are remapped to the
// surviving entry, and every surviving entry carries pkg.MergeInfo describing the fold.
//
// The report is returned so it can be serialized next to the SBOM. Passing a nil SBOM returns an
// empty result.
func MergeSBOM(s *sbom.SBOM, opts identity.Options) identity.Result {
	if s == nil || s.Artifacts.Packages == nil {
		return identity.Merge(nil, opts)
	}

	packages := s.Artifacts.Packages.Sorted()
	records := identity.RecordsFromPackages(packages)

	result := identity.Merge(records, opts)

	// map each source package ID to the output component it became
	bySourceID := map[artifact.ID]*pkg.Package{}
	combined := make([]pkg.Package, 0, len(result.Components))
	for i := range result.Components {
		component := &result.Components[i]
		merged := packageFromComponent(component, packages)
		if merged == nil {
			continue
		}
		for _, member := range component.Members {
			bySourceID[artifact.ID(member)] = merged
		}
		combined = append(combined, *merged)
	}

	// preserve any package that somehow produced no component (defensive: identity requires a
	// name, and the collection should not hold nameless packages, but never drop evidence silently)
	for i := range packages {
		p := packages[i]
		if _, ok := bySourceID[p.ID()]; ok {
			continue
		}
		log.WithFields("package", p.String()).Debug("package had no merged component; retaining unchanged")
		combined = append(combined, p)
		bySourceID[p.ID()] = &p
	}

	collection := pkg.NewCollection(combined...)
	s.Artifacts.Packages = collection
	s.Relationships = remapRelationships(s.Relationships, bySourceID)

	// stamp cross references onto the merge info of the affected entries
	attachCrossReferences(s.Artifacts.Packages, result.Report.CrossReferences)

	// retain the report on the SBOM so it can be serialized next to the artifacts
	report := result.Report
	s.IdentityMergeReport = &report

	return result
}

// packageFromComponent builds the surviving pkg.Package for a merged component. It starts from the
// representative source package (chosen deterministically) and then replaces the evidence fields
// with the union so nothing is lost.
func packageFromComponent(component *identity.MergedComponent, packages []pkg.Package) *pkg.Package {
	byID := make(map[string]pkg.Package, len(packages))
	for _, p := range packages {
		byID[string(p.ID())] = p
	}

	// the representative is the deterministic first member ID; it provides the metadata payload
	// shape, language and CPEs that the union view cannot reconstruct.
	var representative *pkg.Package
	for _, member := range component.Members {
		if p, ok := byID[member]; ok {
			chosen := p
			representative = &chosen
			break
		}
	}
	if representative == nil {
		return nil
	}

	out := *representative
	out.Name = component.Name
	out.Version = component.Version
	out.Type = component.Type
	out.PURL = component.PURL
	out.Locations = locationSetFromIdentity(component.Locations)
	out.Licenses = licenseSetFromIdentity(component.Licenses)
	out.CPEs = cpeListFromIdentity(component.ExternalIDs, representative.CPEs)

	// preserve every metadata payload across members, not just the representative's
	out.MergeInfo = mergeInfoFromComponent(component, packages)

	out.SetID()
	return &out
}

func locationSetFromIdentity(locations []identity.Location) file.LocationSet {
	set := file.NewLocationSet()
	for _, l := range locations {
		loc := file.NewLocationFromCoordinates(file.Coordinates{
			RealPath:     l.RealPath,
			FileSystemID: l.LayerID,
			FullPath:     l.Path,
		})
		if l.AccessPath != "" {
			loc.AccessPath = l.AccessPath
		}
		if l.Evidence != "" {
			loc = loc.WithAnnotation(pkg.EvidenceAnnotationKey, l.Evidence)
		}
		set.Add(loc)
	}
	return set
}

func licenseSetFromIdentity(licenses []identity.License) pkg.LicenseSet {
	set := pkg.NewLicenseSet()
	for _, l := range licenses {
		lic := pkg.License{
			Value:          l.Value,
			SPDXExpression: l.SPDXExpression,
			Locations:      locationSetFromIdentity(l.Locations),
		}
		if l.Type != "" {
			lic.Type = license.Type(l.Type)
		}
		lic.URLs = append([]string{}, l.URLs...)
		set.Add(lic)
	}
	return set
}

func cpeListFromIdentity(externalIDs []identity.ExternalID, original []cpe.CPE) []cpe.CPE {
	// CPEs are already retained on the representative package. If the union contains a CPE the
	// representative does not, add it back through the identity external IDs.
	known := make(map[string]struct{}, len(original))
	for _, c := range original {
		known[c.Attributes.BindToFmtString()+"\x00"+c.Source.String()] = struct{}{}
	}
	out := append([]cpe.CPE{}, original...)
	for _, id := range externalIDs {
		if id.Type != "cpe" {
			continue
		}
		key := id.Value + "\x00" + id.Source
		if _, ok := known[key]; ok {
			continue
		}
		parsed, err := cpe.New(id.Value, cpe.Source(id.Source))
		if err != nil {
			continue
		}
		out = append(out, parsed)
		known[key] = struct{}{}
	}
	return out
}

func mergeInfoFromComponent(component *identity.MergedComponent, packages []pkg.Package) *pkg.MergeInfo {
	info := &pkg.MergeInfo{
		State:         component.State,
		Identity:      component.Identity,
		Namespace:     component.Namespace,
		Versions:      component.Versions,
		Sources:       component.Sources,
		Rules:         component.Rules,
		Members:       component.Members,
		MetadataTypes: component.MetadataTypes,
		LocationCount: len(component.Locations),
		LicenseCount:  len(component.Licenses),
		ChecksumCount: len(component.Checksums),
	}

	for _, c := range component.Checksums {
		info.Checksums = append(info.Checksums, pkg.MergeChecksum{
			Algorithm: c.Algorithm,
			Value:     c.Value,
			Source:    c.Source,
		})
	}
	// CPEs are already on the package's cpes field (the union above re-adds any the representative
	// lacked), so only the purl identifiers are recorded here. A merged entry keeps one purl in its
	// purl field, and these rows retain every purl spelling the sources supplied.
	for _, id := range component.ExternalIDs {
		if id.Type != "purl" {
			continue
		}
		info.ExternalIdentifiers = append(info.ExternalIdentifiers, pkg.MergeExternalID{
			Type:   id.Type,
			Value:  id.Value,
			Source: id.Source,
		})
	}
	for _, conflict := range component.Conflicts {
		info.Conflicts = append(info.Conflicts, pkg.MergeConflict{
			Field:      conflict.Field,
			Values:     conflict.Values,
			Resolution: conflict.Resolution,
			Rule:       conflict.Rule,
			Note:       conflict.Note,
		})
	}

	// Keep every member's metadata payload so the representative metadata field is not the only
	// surviving description of the component.
	byID := make(map[string]pkg.Package, len(packages))
	for _, p := range packages {
		byID[string(p.ID())] = p
	}
	for _, member := range component.Members {
		p, ok := byID[member]
		if !ok || p.Metadata == nil {
			continue
		}
		payload, err := json.Marshal(p.Metadata)
		if err != nil {
			continue
		}
		info.MetadataPayloads = append(info.MetadataPayloads, pkg.MergeMetadata{
			Type:    identity.MetadataTypeName(p.Metadata),
			Payload: payload,
		})
	}

	return info
}

// attachCrossReferences records the cross-type links on both entries' merge info.
func attachCrossReferences(collection *pkg.Collection, refs []identity.CrossReference) {
	byID := map[artifact.ID][]string{}
	for _, ref := range refs {
		byID[artifact.ID(ref.LeftID)] = append(byID[artifact.ID(ref.LeftID)], ref.RightID)
		byID[artifact.ID(ref.RightID)] = append(byID[artifact.ID(ref.RightID)], ref.LeftID)
	}
	if len(byID) == 0 {
		return
	}

	updates := map[artifact.ID]pkg.Package{}
	for p := range collection.Enumerate() {
		linked, ok := byID[p.ID()]
		if !ok {
			continue
		}
		info := p.MergeInfo
		if info == nil {
			info = &pkg.MergeInfo{State: "unique"}
		}
		info.CrossReferences = uniqueSorted(linked)
		p.MergeInfo = info
		updates[p.ID()] = p
	}
	for _, p := range updates {
		collection.Add(p)
	}
}

// remapRelationships rewrites every relationship endpoint to the surviving merged package. Two
// endpoints that folded into the same entry would form a self-edge, which is dropped: the
// relationship described the same component twice.
func remapRelationships(relationships []artifact.Relationship, bySourceID map[artifact.ID]*pkg.Package) []artifact.Relationship {
	if len(relationships) == 0 {
		return relationships
	}
	index := newRelationshipIndex()
	for _, r := range relationships {
		from := remapEndpoint(r.From, bySourceID)
		to := remapEndpoint(r.To, bySourceID)
		if from == nil || to == nil || from.ID() == to.ID() {
			continue
		}
		index.add(artifact.Relationship{From: from, To: to, Type: r.Type, Data: r.Data})
	}
	return index.all()
}

// remapEndpoint returns the surviving endpoint for a relationship side. Package endpoints are
// replaced with their merged package; non-package endpoints pass through unchanged.
func remapEndpoint(endpoint artifact.Identifiable, bySourceID map[artifact.ID]*pkg.Package) artifact.Identifiable {
	if endpoint == nil {
		return nil
	}
	if merged, ok := bySourceID[endpoint.ID()]; ok {
		return *merged
	}
	return endpoint
}

// relationshipIndex de-duplicates relationships while preserving a stable order.
type relationshipIndex struct {
	seen  map[string]artifact.Relationship
	order []string
}

func newRelationshipIndex() *relationshipIndex {
	return &relationshipIndex{seen: map[string]artifact.Relationship{}}
}

func (i *relationshipIndex) add(r artifact.Relationship) {
	key := relationshipKey(r)
	if _, ok := i.seen[key]; ok {
		return
	}
	i.seen[key] = r
	i.order = append(i.order, key)
}

func (i *relationshipIndex) all() []artifact.Relationship {
	out := make([]artifact.Relationship, 0, len(i.order))
	for _, key := range i.order {
		out = append(out, i.seen[key])
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].From.ID() != out[b].From.ID() {
			return out[a].From.ID() < out[b].From.ID()
		}
		if out[a].To.ID() != out[b].To.ID() {
			return out[a].To.ID() < out[b].To.ID()
		}
		return out[a].Type < out[b].Type
	})
	return out
}

// uniqueSorted returns the sorted, de-duplicated form of the input.
func uniqueSorted(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func relationshipKey(r artifact.Relationship) string {
	return strings.Join([]string{
		string(r.Type),
		string(r.From.ID()),
		string(r.To.ID()),
	}, "\x00")
}
