package identity

import "github.com/anchore/syft/syft/pkg"

// The Rec/Loc/Sum/PURL/ExtID helpers build records for scenarios. They live in the non-test
// package so the checked-in report generator and the unit tests share exactly one definition.

// RecOption mutates a record while a scenario is being built.
type RecOption func(*Record)

// Rec builds a record with the fields the merge cares about.
func Rec(id, name, version string, ty pkg.Type, foundBy string, opts ...RecOption) Record {
	r := Record{ID: id, Name: name, Version: version, Type: ty, FoundBy: foundBy}
	for _, opt := range opts {
		opt(&r)
	}
	return r
}

// Loc adds a location to a record.
func Loc(path string) RecOption {
	return func(r *Record) {
		r.Locations = append(r.Locations, Location{Path: path, AccessPath: path})
	}
}

// Lic adds a license (with its location) to a record.
func Lic(value, path string) RecOption {
	return func(r *Record) {
		r.Licenses = append(r.Licenses, License{Value: value, Locations: []Location{{Path: path}}})
	}
}

// Sum adds a checksum to a record.
func Sum(algorithm, value, source string) RecOption {
	return func(r *Record) {
		r.Checksums = append(r.Checksums, Checksum{Algorithm: algorithm, Value: value, Source: source})
	}
}

// PURL sets the record's package URL.
func PURL(purl string) RecOption {
	return func(r *Record) { r.PURL = purl }
}

// ExtID adds an external identifier to a record.
func ExtID(ty, value, source string) RecOption {
	return func(r *Record) {
		r.ExternalIDs = append(r.ExternalIDs, ExternalID{Type: ty, Value: value, Source: source})
	}
}
