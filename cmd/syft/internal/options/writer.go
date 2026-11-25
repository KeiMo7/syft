package options

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/go-homedir"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/sbomartifact"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/table"
	"github.com/anchore/syft/syft/sbom"
)

var _ interface {
	io.Closer
	sbom.Writer
} = (*sbomMultiWriter)(nil)

// makeSBOMWriter creates a sbom.Writer for output or returns an error. this will either return a valid writer
// or an error but neither both and if there is no error, sbom.Writer.Close() should be called
func makeSBOMWriter(outputs []string, defaultFile string, encoders []sbom.FormatEncoder) (sbom.Writer, error) {
	outputOptions, err := parseSBOMOutputFlags(outputs, defaultFile, encoders)
	if err != nil {
		return nil, err
	}

	writer, err := newSBOMMultiWriter(outputOptions...)
	if err != nil {
		return nil, err
	}

	return writer, nil
}

// parseSBOMOutputFlags utility to parse command-line option strings and retain the existing behavior of default format and file
func parseSBOMOutputFlags(outputs []string, defaultFile string, encoders []sbom.FormatEncoder) (out []sbomWriterDescription, errs error) {
	encoderCollection := format.NewEncoderCollection(encoders...)

	// always should have one option -- we generally get the default of "table", but just make sure
	if len(outputs) == 0 {
		outputs = append(outputs, table.ID.String())
	}

	for _, name := range outputs {
		name = strings.TrimSpace(name)

		// split to at most two parts for <format>=<file>
		parts := strings.SplitN(name, "=", 2)

		// the format name is the first part
		name = parts[0]

		// default to the --file or empty string if not specified
		file := defaultFile

		// If a file is specified as part of the output formatName, use that
		if len(parts) > 1 {
			file = parts[1]
		}

		enc := encoderCollection.GetByString(name)
		if enc == nil {
			errs = multierror.Append(errs, fmt.Errorf(`unsupported output format "%s", supported formats are: %+v`, name, formatVersionOptions(encoderCollection.NameVersions())))
			continue
		}

		out = append(out, newSBOMWriterDescription(enc, file))
	}
	return out, errs
}

// formatVersionOptions takes a list like ["github-json", "syft-json@11.0.0", "cyclonedx-xml@1.0", "cyclondx-xml@1.1"...]
// and formats it into a human-readable string like:
//
// Available formats:
//   - cyclonedx-json @ 1.2, 1.3, 1.4, 1.5
//   - cyclonedx-xml @ 1.0, 1.1, 1.2, 1.3, 1.4, 1.5
//   - github-json
//   - spdx-json @ 2.2, 2.3
//   - spdx-tag-value @ 2.1, 2.2, 2.3
//   - syft-json
//   - syft-table
//   - syft-text
//   - template
func formatVersionOptions(nameVersionPairs []string) string {
	availableVersions := make(map[string][]string)
	availableFormats := strset.New()
	for _, nameVersion := range nameVersionPairs {
		fields := strings.SplitN(nameVersion, "@", 2)
		if len(fields) == 2 {
			availableVersions[fields[0]] = append(availableVersions[fields[0]], fields[1])
		}
		availableFormats.Add(fields[0])
	}

	// find any formats with exactly one version -- remove them from the version map
	for name, versions := range availableVersions {
		if len(versions) == 1 {
			delete(availableVersions, name)
		}
	}

	sortedAvailableFormats := availableFormats.List()
	sort.Strings(sortedAvailableFormats)

	var s strings.Builder

	s.WriteString("\n")
	s.WriteString("Available formats:")

	for _, name := range sortedAvailableFormats {
		s.WriteString("\n")

		fmt.Fprintf(&s, "   - %s", name)

		if len(availableVersions[name]) > 0 {
			s.WriteString(" @ ")
			s.WriteString(strings.Join(availableVersions[name], ", "))
		}
	}

	return s.String()
}

// sbomWriterDescription Format and path strings used to create sbom.Writer
type sbomWriterDescription struct {
	Format sbom.FormatEncoder
	Path   string
}

func newSBOMWriterDescription(f sbom.FormatEncoder, p string) sbomWriterDescription {
	expandedPath, err := homedir.Expand(p)
	if err != nil {
		log.Warnf("could not expand given writer output path=%q: %w", p, err)
		// ignore errors
		expandedPath = p
	}
	return sbomWriterDescription{
		Format: f,
		Path:   expandedPath,
	}
}

// sbomMultiWriter holds a list of child sbom.Writers to apply all Write and Close operations to.
// Path-less outputs keep streaming to the report bus (terminal output); every output with a path
// is handed to the atomic persistence batch, which covers single files, directory bundles and
// archive bundles behind one implementation.
type sbomMultiWriter struct {
	publishers []*sbomPublisher
	batch      *sbomartifact.Batch
}

// newSBOMMultiWriter create all report writers from input options; if a file is not specified the given defaultWriter is used.
// No destination is opened or created here: all filesystem work happens in Write, inside the
// atomic batch, so a later failure cannot leave partially opened files behind.
func newSBOMMultiWriter(options ...sbomWriterDescription) (_ *sbomMultiWriter, err error) {
	if len(options) == 0 {
		return nil, fmt.Errorf("no output options provided")
	}

	out := &sbomMultiWriter{}

	var requests []sbomartifact.Request
	requestByPath := make(map[string]int)

	for _, option := range options {
		if option.Path == "" {
			out.publishers = append(out.publishers, &sbomPublisher{format: option.Format})
			continue
		}

		if idx, ok := requestByPath[option.Path]; ok {
			requests[idx].Encoders = append(requests[idx].Encoders, option.Format)
		} else {
			requestByPath[option.Path] = len(requests)
			requests = append(requests, sbomartifact.Request{
				Path:     option.Path,
				Encoders: []sbom.FormatEncoder{option.Format},
			})
		}
	}

	if len(requests) > 0 {
		// validation (path shape, duplicate single-file conflicts, empty format sets) happens here,
		// before any target becomes visible; locking is also acquired up front.
		batch, err := sbomartifact.NewBatch(context.Background(), requests...)
		if err != nil {
			return nil, err
		}
		out.batch = batch
	}

	return out, nil
}

// Write writes the SBOM to all writers. Terminal outputs are encoded independently so a busy
// report bus can never touch a persistence target, and the batch itself is all-or-nothing.
func (m *sbomMultiWriter) Write(s sbom.SBOM) (errs error) {
	for _, p := range m.publishers {
		if err := p.Write(s); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("unable to write SBOM: %w", err))
		}
	}
	if m.batch != nil {
		if err := m.batch.Write(s); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("unable to write SBOM: %w", err))
		}
	}
	return errs
}

// Close releases any locks held by an unwritten batch (for example when a scan fails after the
// writer was constructed). Successful writes release their locks inside Write.
func (m *sbomMultiWriter) Close() error {
	var errs error
	if m.batch != nil {
		if err := m.batch.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			errs = multierror.Append(errs, err)
		}
	}
	return errs
}

// sbomPublisher implements sbom.Writer that publishes results to the event bus
type sbomPublisher struct {
	format sbom.FormatEncoder
}

// Write the provided SBOM to the data stream
func (w *sbomPublisher) Write(s sbom.SBOM) error {
	buf := &bytes.Buffer{}
	if err := w.format.Encode(buf, s); err != nil {
		return fmt.Errorf("unable to encode SBOM: %w", err)
	}

	bus.Report(buf.String())
	return nil
}
