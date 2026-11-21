package timeline

import (
	"fmt"
	"os"

	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
)

// decodeDocument reads and decodes one SBOM document in any format syft understands.
func decodeDocument(path string) (*sbom.SBOM, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open SBOM %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	s, _, _, err := format.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("unable to decode SBOM %q: %w", path, err)
	}
	if s == nil {
		return nil, fmt.Errorf("SBOM %q is empty", path)
	}
	return s, nil
}
