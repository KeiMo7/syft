package sbomartifact

// target is one resolved output destination: a single file, a directory bundle, or an archive
// bundle. Every implementation assembles its complete content in private staging first and only
// touches its visible destination during Commit; Rollback restores whatever existed before.
//
// Stage receives the batch's shared encoded members and the target-specific index bytes so all
// targets of one run derive from a single encode per format — directory and archive members are
// therefore byte-identical by construction.
type target interface {
	// Path is the user-visible destination path.
	Path() string
	// Kind reports the materialized form.
	Kind() TargetKind
	// Stage builds the complete target in a private location without touching the visible path.
	Stage(members []*encodedMember, indexBytes []byte) error
	// Commit swaps staged content into place atomically, preserving prior content as a backup.
	Commit() error
	// Finalize removes pre-call backups once the whole batch has committed.
	Finalize() error
	// Rollback discards staging and restores the pre-call visible state.
	Rollback() error
}

// indexMemberSelector is implemented by bundle targets (directory and archive) that emit an
// index.json. The returned names select the target's members from the batch's shared encoded set.
type indexMemberSelector interface {
	indexMembers() []string
}
