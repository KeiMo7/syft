package sbomartifact

import (
	"errors"
	"fmt"

	"github.com/anchore/syft/syft/sbom"
)

// joinErr combines two errors without pulling in extra dependency surface for the package.
func joinErr(existing, add error) error {
	if existing == nil {
		return add
	}
	return errors.Join(existing, add)
}

// errEmptyTarget marks an output destination that resolved to zero encoders; such a request must
// never create an empty directory or archive as a "successful" result.
type errEmptyTarget struct {
	path string
	kind TargetKind
}

func (e *errEmptyTarget) Error() string {
	return "no output formats resolved for " + e.kind.String() + " target " + e.path
}

// EncodeError pinpoints the format and destination that failed while producing a member, so batch
// failures never surface as an anonymous template/encoder error.
type EncodeError struct {
	Path    string
	Kind    TargetKind
	Format  string
	Version string
	Err     error
}

func (e *EncodeError) Error() string {
	version := e.Version
	if version == "" || version == sbom.AnyVersion {
		version = "default"
	}
	return fmt.Sprintf("unable to encode %s@%s for %s target %q: %v", e.Format, version, e.Kind, e.Path, e.Err)
}

func (e *EncodeError) Unwrap() error { return e.Err }
