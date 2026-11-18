package options

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/sbom"
)

type errorEncoder struct {
	payload string
}

func (e errorEncoder) ID() sbom.FormatID { return "error" }
func (e errorEncoder) Aliases() []string { return nil }
func (e errorEncoder) Version() string   { return sbom.AnyVersion }
func (e errorEncoder) Encode(w io.Writer, _ sbom.SBOM) error {
	_, _ = w.Write([]byte(e.payload))
	return errors.New("interrupted")
}

type successEncoder struct {
	payload string
}

func (e successEncoder) ID() sbom.FormatID { return "success" }
func (e successEncoder) Aliases() []string { return nil }
func (e successEncoder) Version() string   { return sbom.AnyVersion }
func (e successEncoder) Encode(w io.Writer, _ sbom.SBOM) error {
	_, err := w.Write([]byte(e.payload))
	return err
}

func TestSBOMStreamWriterLeavesIncompleteMarkerOnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "result.json")
	require.NoError(t, os.WriteFile(path, []byte("previous complete result"), 0o600))

	writer, err := newSBOMMultiWriter(newSBOMWriterDescription(errorEncoder{payload: "partial"}, path))
	require.NoError(t, err)

	err = writer.Write(sbom.SBOM{})
	require.Error(t, err)
	assert.FileExists(t, path+".incomplete")
	contents, readErr := os.ReadFile(path + ".incomplete")
	require.NoError(t, readErr)
	assert.Equal(t, "partial", string(contents))

	previous, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, "previous complete result", string(previous))
}

func TestSBOMStreamWriterAtomicallyPublishesOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "result.json")

	writer, err := newSBOMMultiWriter(newSBOMWriterDescription(successEncoder{payload: "complete"}, path))
	require.NoError(t, err)
	require.NoError(t, writer.Write(sbom.SBOM{}))

	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "complete", string(contents))
	assert.NoFileExists(t, path+".incomplete")
}
