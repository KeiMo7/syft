package commands

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/cmd/syft/internal/options"
	"github.com/anchore/syft/syft/cataloging/exclusions"
)

func Test_setDefaultExclusionAuditFile(t *testing.T) {
	tests := []struct {
		name string
		opts scanOptions
		want string
	}{
		{
			name: "disabled without rules",
			opts: scanOptions{},
			want: "",
		},
		{
			name: "uses output sidecar",
			opts: scanOptions{
				Output: options.Output{Outputs: []string{"syft-json=sbom.json"}},
				Catalog: options.Catalog{
					ExclusionRules: []exclusions.RuleConfig{{Ecosystem: "npm"}},
				},
			},
			want: "sbom.json.exclusions.json",
		},
		{
			name: "uses stdout fallback",
			opts: scanOptions{
				Catalog: options.Catalog{
					ExclusionRules: []exclusions.RuleConfig{{Ecosystem: "npm"}},
				},
			},
			want: "syft-exclusions.json",
		},
		{
			name: "preserves explicit path",
			opts: scanOptions{
				Catalog: options.Catalog{
					ExclusionRules:     []exclusions.RuleConfig{{Ecosystem: "npm"}},
					ExclusionAuditFile: "custom.json",
				},
			},
			want: "custom.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setDefaultExclusionAuditFile(&tt.opts)
			assert.Equal(t, tt.want, tt.opts.Catalog.ExclusionAuditFile)
		})
	}
}

func Test_scanOptions_validateLegacyOptionsNotUsed(t *testing.T) {
	tests := []struct {
		name    string
		cfg     string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "no config file",
		},
		{
			name: "config file with no legacy options",
			cfg:  "testdata/scan-configs/no-legacy-options.yaml",
		},
		{
			name:    "config file with default image pull source legacy option",
			cfg:     "testdata/scan-configs/with-default-pull-source.yaml",
			wantErr: assertErrorContains("source.image.default-pull-source"),
		},
		{
			name:    "config file with exclude-binary-overlap-by-ownership legacy option",
			cfg:     "testdata/scan-configs/with-exclude-binary-overlap-by-ownership.yaml",
			wantErr: assertErrorContains("package.exclude-binary-overlap-by-ownership"),
		},
		{
			name:    "config file with file string legacy option",
			cfg:     "testdata/scan-configs/with-file-string.yaml",
			wantErr: assertErrorContains("outputs"),
		},
		{
			name: "config file with file section",
			cfg:  "testdata/scan-configs/with-file-section.yaml",
		},
		{
			name:    "config file with base-path legacy option",
			cfg:     "testdata/scan-configs/with-base-path.yaml",
			wantErr: assertErrorContains("source.base-path"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}
			o := &scanOptions{
				Config: options.Config{ConfigFile: tt.cfg},
			}
			tt.wantErr(t, o.validateLegacyOptionsNotUsed())
		})
	}
}

func assertErrorContains(contains string) assert.ErrorAssertionFunc {
	return func(t assert.TestingT, err error, i ...any) bool {
		return assert.ErrorContains(t, err, contains, i...)
	}
}
