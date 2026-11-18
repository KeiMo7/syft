package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/trim"
)

func TestOutputPostLoadRejectsUnknownTrimCategory(t *testing.T) {
	output := Output{
		Trim: trim.Config{
			Enabled: true,
			Default: trim.Policy{
				Categories: map[string]bool{"development": true},
			},
		},
	}

	err := output.PostLoad()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown trim category "development"`)
	assert.Contains(t, err.Error(), "build, dev, test")
}
