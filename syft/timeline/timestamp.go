package timeline

import (
	"fmt"
	"strings"
	"time"
)

// TimestampLayout is the one timestamp representation used on the timeline: UTC with exactly
// millisecond precision. Every record written through this package is normalized to this
// layout, so a batch never mixes timezones or precisions.
//
// The offset is always rendered as "Z" because timestamps are converted to UTC first.
const TimestampLayout = "2006-01-02T15:04:05.000Z07:00"

const timestampPrecision = time.Millisecond

var acceptedTimestampLayouts = []string{
	TimestampLayout,
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.000",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04",
	"2006-01-02",
}

// NormalizeTimestamp converts any timestamp to the single canonical timeline representation:
// UTC with millisecond precision.
func NormalizeTimestamp(t time.Time) time.Time {
	return t.UTC().Truncate(timestampPrecision)
}

// FormatTimestamp renders a timestamp in the canonical timeline representation.
func FormatTimestamp(t time.Time) string {
	return NormalizeTimestamp(t).Format(TimestampLayout)
}

// ParseTimestamp accepts the canonical representation as well as the common date and
// date-time forms a user is likely to type, and normalizes whatever was given to UTC with
// millisecond precision. Values without a zone are interpreted as UTC.
func ParseTimestamp(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, fmt.Errorf("empty timestamp")
	}

	for _, layout := range acceptedTimestampLayouts {
		if t, err := time.ParseInLocation(layout, value, time.UTC); err == nil {
			return NormalizeTimestamp(t), nil
		}
	}

	return time.Time{}, fmt.Errorf("unrecognized timestamp %q (expected UTC RFC3339, e.g. 2026-11-01T00:00:00.000Z)", value)
}
