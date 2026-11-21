package timeline

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

// appendPoint is the part of the journal an append needs to consult: the newest timestamp and the
// snapshots recorded at a specific timestamp.
type appendPoint struct {
	newestTimestamp string
	// atTimestamp maps snapshot ID to whether it exists at the queried timestamp. Duplicates can
	// only exist at the same timestamp, because a record's identity includes its timestamp.
	atTimestamp map[string]struct{}
}

// inspectTail reads the journal backwards far enough to answer the two questions an append asks:
// what is the newest timestamp, and is this snapshot already recorded at its own timestamp?
//
// Because both writers keep the journal ordered by timestamp, only the final run of lines can
// share the queried timestamp. A live append therefore touches a constant number of lines no
// matter how large the history has grown.
func inspectTail(path, timestamp string) (appendPoint, error) {
	point := appendPoint{atTimestamp: make(map[string]struct{})}

	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return point, nil
	}
	if err != nil {
		return point, fmt.Errorf("unable to open history journal %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return point, fmt.Errorf("unable to stat history journal %q: %w", path, err)
	}

	r := &reverseLineReader{file: f, offset: info.Size()}
	for {
		data, err := r.previous()
		if errors.Is(err, io.EOF) {
			return point, nil
		}
		if err != nil {
			return point, fmt.Errorf("unable to read history journal %q: %w", path, err)
		}
		if len(bytes.TrimSpace(data)) == 0 {
			continue
		}

		snapshotID, lineTimestamp, err := decodeRecordHeader(data)
		if err != nil {
			// a damaged line cannot contribute to either answer, but it also must not stop the
			// scan: the newest intact timestamp is what matters
			continue
		}

		if point.newestTimestamp == "" {
			point.newestTimestamp = lineTimestamp
		}

		// lines are ordered, so the first line older than the queried timestamp ends the
		// relevant run
		if lineTimestamp < timestamp {
			return point, nil
		}
		if lineTimestamp == timestamp {
			point.atTimestamp[snapshotID] = struct{}{}
		}
	}
}

// reverseLineReader yields lines from the end of a file without loading it. Each call returns the
// next line towards the start, without its trailing newline.
type reverseLineReader struct {
	file   *os.File
	offset int64
	buf    []byte
}

const reverseChunkSize = 32 * 1024

func (r *reverseLineReader) previous() ([]byte, error) {
	for {
		if i := bytes.LastIndexByte(r.buf, '\n'); i >= 0 {
			line := r.buf[i+1:]
			r.buf = r.buf[:i]
			// a trailing newline at the end of the file yields one empty final segment, which the
			// caller skips; stripping \r keeps the reader identical to the forward one
			return bytes.TrimSuffix(append([]byte{}, line...), []byte{'\r'}), nil
		}

		if r.offset == 0 {
			if len(r.buf) == 0 {
				return nil, io.EOF
			}
			line := r.buf
			r.buf = nil
			return bytes.TrimSuffix(append([]byte{}, line...), []byte{'\r'}), nil
		}

		start := r.offset - reverseChunkSize
		if start < 0 {
			start = 0
		}
		chunk := make([]byte, r.offset-start)
		if _, err := r.file.ReadAt(chunk, start); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		r.offset = start
		r.buf = append(chunk, r.buf...)
	}
}
