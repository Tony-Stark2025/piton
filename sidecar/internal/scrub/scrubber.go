package scrub

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/url"
	"sort"
	"strings"
)

const RedactionMarker = "[REDACTED_BY_PROMETHEUS]"

// SlidingWindowScrubber scrubs active secrets (raw, base64, URL-encoded, and JSON-escaped
// variants) from streaming HTTP / SSE response bodies while holding back `maxSecretLen - 1`
// trailing bytes across Write boundaries so chunk-split secrets cannot slip through.
type SlidingWindowScrubber struct {
	dst          io.Writer
	variants     [][]byte
	maxSecretLen int
	tail         []byte
	RedactedHits int
}

// ExpandSecretVariants builds raw + base64 + URL-encoded + JSON-escaped forms for a secret.
func ExpandSecretVariants(secrets []string) [][]byte {
	seen := make(map[string]struct{})
	var rawList []string
	add := func(s string) {
		if len(s) < 6 {
			return
		}
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			rawList = append(rawList, s)
		}
	}

	for _, sec := range secrets {
		sec = strings.TrimSpace(sec)
		if len(sec) < 6 {
			continue
		}
		add(sec)
		add(base64.StdEncoding.EncodeToString([]byte(sec)))
		add(base64.RawStdEncoding.EncodeToString([]byte(sec)))
		add(base64.RawURLEncoding.EncodeToString([]byte(sec)))
		add(url.QueryEscape(sec))
		if jb, err := json.Marshal(sec); err == nil && len(jb) >= 2 {
			add(string(jb[1 : len(jb)-1]))
		}
	}

	// Longest-first avoids partial redactions when one variant is a substring of another.
	sort.Slice(rawList, func(i, j int) bool {
		if len(rawList[i]) == len(rawList[j]) {
			return rawList[i] < rawList[j]
		}
		return len(rawList[i]) > len(rawList[j])
	})

	out := make([][]byte, 0, len(rawList))
	for _, s := range rawList {
		out = append(out, []byte(s))
	}
	return out
}

func NewSlidingWindowScrubber(dst io.Writer, secrets []string) *SlidingWindowScrubber {
	variants := ExpandSecretVariants(secrets)
	maxLen := 0
	for _, v := range variants {
		if len(v) > maxLen {
			maxLen = len(v)
		}
	}
	return &SlidingWindowScrubber{
		dst:          dst,
		variants:     variants,
		maxSecretLen: maxLen,
	}
}

func (s *SlidingWindowScrubber) scrubBuffer(buf []byte) []byte {
	marker := []byte(RedactionMarker)
	out := buf
	for _, v := range s.variants {
		if bytes.Contains(out, v) {
			s.RedactedHits += bytes.Count(out, v)
			out = bytes.ReplaceAll(out, v, marker)
		}
	}
	return out
}

// Write processes a chunk while retaining up to `maxSecretLen - 1` trailing bytes
// for cross-chunk boundary matching.
func (s *SlidingWindowScrubber) Write(p []byte) (int, error) {
	if len(s.variants) == 0 || s.maxSecretLen <= 1 {
		return s.dst.Write(p)
	}
	combined := make([]byte, 0, len(s.tail)+len(p))
	combined = append(combined, s.tail...)
	combined = append(combined, p...)

	cleaned := s.scrubBuffer(combined)
	keep := s.maxSecretLen - 1
	if len(cleaned) <= keep {
		s.tail = cleaned
		return len(p), nil
	}
	emitLen := len(cleaned) - keep
	if _, err := s.dst.Write(cleaned[:emitLen]); err != nil {
		return 0, err
	}
	s.tail = append([]byte(nil), cleaned[emitLen:]...)
	return len(p), nil
}

// Flush scrubs and emits any remaining buffered tail bytes at EOF.
func (s *SlidingWindowScrubber) Flush() error {
	if len(s.tail) == 0 {
		return nil
	}
	cleaned := s.scrubBuffer(s.tail)
	s.tail = nil
	_, err := s.dst.Write(cleaned)
	return err
}

// ScrubBytes is a convenience helper for bounded payloads.
func ScrubBytes(data []byte, secrets []string) ([]byte, int) {
	var buf bytes.Buffer
	sc := NewSlidingWindowScrubber(&buf, secrets)
	_, _ = sc.Write(data)
	_ = sc.Flush()
	return buf.Bytes(), sc.RedactedHits
}
