package diff

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
)

func sampleReport() Report {
	changes := []Change{
		{
			Type:          Added,
			Name:          "new-lib",
			ComponentType: pkg.NpmPkg,
			NewVersion:    "1.0.0",
			IdentityKey:   "purl:pkg:npm/new-lib",
			IdentityRule:  PURLIdentity,
			NewLayer:      DirectDependency,
			HighRisk:      true,
		},
		{
			Type:          VersionChanged,
			Direction:     Downgrade,
			Name:          "old-lib",
			ComponentType: pkg.NpmPkg,
			OldVersion:    "2.0.0",
			NewVersion:    "1.0.0",
			IdentityKey:   "purl:pkg:npm/old-lib",
			IdentityRule:  PURLIdentity,
			OldLayer:      TransitiveDependency,
			NewLayer:      TransitiveDependency,
			HighRisk:      true,
		},
	}

	report := NewReport(
		InputDescription{Path: "old.json", FormatID: "syft-json", SchemaVersion: "16.1.13", SourceType: "image"},
		InputDescription{Path: "new.json", FormatID: "syft-json", SchemaVersion: "16.1.13", SourceType: "directory"},
		changes,
		Options{},
	)

	return report
}

func TestWriteJSONIsMachineReadable(t *testing.T) {
	var buffer bytes.Buffer
	require.NoError(t, WriteJSON(&buffer, sampleReport()))

	var decoded Report
	require.NoError(t, json.Unmarshal(buffer.Bytes(), &decoded))

	assert.Equal(t, ReportVersion, decoded.ReportSchema)
	assert.True(t, decoded.SourceMismatch)
	assert.Len(t, decoded.Changes, 2)
	assert.Equal(t, 2, decoded.Counts.HighRisk)
}

func TestWriteJSONLStreamsHeaderAndOneChangePerLine(t *testing.T) {
	var buffer bytes.Buffer
	require.NoError(t, WriteJSONL(&buffer, sampleReport()))

	lines := strings.Split(strings.TrimSpace(buffer.String()), "\n")
	require.Len(t, lines, 3)

	var header Report
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &header))
	assert.Equal(t, ReportVersion, header.ReportSchema)
	assert.Nil(t, header.Changes)
	assert.Equal(t, 2, header.TotalChanges)

	for _, line := range lines[1:] {
		var change Change
		require.NoError(t, json.Unmarshal([]byte(line), &change))
		assert.NotEmpty(t, change.IdentityKey)
	}
}

func TestWriteTableContainsGroupsAndSummary(t *testing.T) {
	var buffer bytes.Buffer
	require.NoError(t, WriteTable(&buffer, sampleReport()))

	output := buffer.String()
	assert.Contains(t, output, "summary: added=1 removed=0 version-changed=1")
	assert.Contains(t, output, "Added components (1):")
	assert.Contains(t, output, "Version changes (1):")
	assert.Contains(t, output, "downgrade")
	assert.Contains(t, output, "high-risk")
	assert.Contains(t, output, "WARNING: source types differ")
}

func TestWriteTableEmptyChanges(t *testing.T) {
	report := NewReport(InputDescription{}, InputDescription{}, nil, Options{})

	var buffer bytes.Buffer
	require.NoError(t, WriteTable(&buffer, report))

	assert.Contains(t, buffer.String(), "no component changes detected")
}
