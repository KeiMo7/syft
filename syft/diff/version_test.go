package diff

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name     string
		old      string
		new      string
		expected VersionChangeDirection
	}{
		{name: "minor upgrade", old: "1.2.3", new: "1.3.0", expected: Upgrade},
		{name: "major upgrade", old: "1.2.3", new: "2.0.0", expected: Upgrade},
		{name: "downgrade", old: "2.0.0", new: "1.9.0", expected: Downgrade},
		{name: "revision only", old: "1.2.3", new: "1.2.4", expected: RevisionOnly},
		{name: "leading v", old: "v1.2.3", new: "v1.2.4", expected: RevisionOnly},
		{name: "epoch prefix", old: "1:1.2.3", new: "1:2.0.0", expected: Upgrade},
		{name: "prerelease to release", old: "1.0.0-rc1", new: "1.0.0", expected: Upgrade},
		{name: "date based uncomparable", old: "20240101", new: "20240202", expected: NoDirection},
		{name: "arbitrary text uncomparable", old: "stable", new: "edge", expected: NoDirection},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, compareVersions(tt.old, tt.new))
		})
	}
}

func TestPURLIdentityKey(t *testing.T) {
	key, ok := purlIdentityKey("pkg:npm/my-lib@1.2.3?vcs_url=git%2Bhttps%3A%2F%2Fexample.com%2Frepo")
	require.True(t, ok)
	assert.Equal(t, "purl:pkg:npm/my-lib?vcs_url=git%2Bhttps%3A%2F%2Fexample.com%2Frepo", key)

	_, ok = purlIdentityKey("not a purl")
	assert.False(t, ok)
}

func TestPagination(t *testing.T) {
	changes := []Change{
		{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}, {Name: "e"},
	}

	page, pageNumber := Paginate(changes, Pagination{Page: 1, PageSize: 2})
	assert.Equal(t, 1, pageNumber)
	assert.Equal(t, []string{"a", "b"}, []string{page[0].Name, page[1].Name})

	page, pageNumber = Paginate(changes, Pagination{Page: 3, PageSize: 2})
	assert.Equal(t, 3, pageNumber)
	assert.Len(t, page, 1)
	assert.Equal(t, "e", page[0].Name)

	page, _ = Paginate(changes, Pagination{Page: 99, PageSize: 2})
	assert.Empty(t, page)

	all, pageNumber := Paginate(changes, Pagination{PageSize: 0})
	assert.Equal(t, 0, pageNumber)
	assert.Len(t, all, 5)
}
