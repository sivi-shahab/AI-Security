// Package extract turns a file into text for the detectors (spec FR-CLS-5), without trusting the file: archive
// depth, decompression ratio, entry count and output size are bounded (§13), and nothing is written to disk.
// Text, CSV/TSV, HTML, JSON/XML, Office Open XML (docx, xlsx, pptx) and zip archives are parsed here, in Go;
// PDF and legacy Office go to a sandboxed Apache Tika server when one is configured.
package extract

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"unicode/utf8"
)

var (
	ErrUnsupported = errors.New("unsupported file type")
	ErrLimit       = errors.New("file exceeds extraction limits") // zip bomb, too deep, too many entries, too big
)

// Limits are spec §13's defaults unless configured otherwise.
type Limits struct {
	MaxBytes   int64 // input file
	MaxDepth   int   // nested archives
	MaxRatio   int64 // total decompressed bytes / input bytes
	MaxEntries int   // across all archives in the file
	MaxText    int   // text handed to the detectors; the rest is cut (Result.Truncated)
}

var Default = Limits{MaxBytes: 50 << 20, MaxDepth: 3, MaxRatio: 100, MaxEntries: 10000, MaxText: 2 << 20}

// Tika is an Apache Tika server (PUT /tika → text/plain). Run it sandboxed (gVisor), without egress.
type Tika struct {
	URL  string
	HTTP *http.Client
}

type Result struct {
	Text      string `json:"-"`
	Format    string `json:"format"`
	Truncated bool   `json:"truncated"`
}

type state struct {
	ctx      context.Context
	l        Limits
	tika     *Tika
	budget   int64 // decompressed bytes left
	entries  int
	out      strings.Builder
	formats  []string
	truncate bool
}

// Extract returns the text of data (file name name). tika may be nil.
func Extract(ctx context.Context, data []byte, name string, l Limits, tika *Tika) (Result, error) {
	if int64(len(data)) > l.MaxBytes {
		return Result{}, fmt.Errorf("%w: %d bytes > %d", ErrLimit, len(data), l.MaxBytes)
	}
	s := &state{ctx: ctx, l: l, tika: tika, budget: l.MaxRatio * max(int64(len(data)), 1)}
	err := s.file(data, name, 0)
	r := Result{Text: s.out.String(), Format: strings.Join(s.formats, ","), Truncated: s.truncate}
	return r, err
}

// write appends text up to MaxText; false once full.
func (s *state) write(t string) bool {
	room := s.l.MaxText - s.out.Len()
	if room <= 0 {
		s.truncate = true
		return false
	}
	if len(t) > room {
		t, s.truncate = t[:room], true
	}
	s.out.WriteString(t)
	return !s.truncate
}

func (s *state) file(data []byte, name string, depth int) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	ext := strings.ToLower(path.Ext(name))
	switch {
	case bytes.HasPrefix(data, []byte("PK\x03\x04")) || bytes.HasPrefix(data, []byte("PK\x05\x06")):
		return s.zip(data, depth)
	case bytes.HasPrefix(data, []byte("%PDF")), bytes.HasPrefix(data, []byte{0xD0, 0xCF, 0x11, 0xE0}), bytes.HasPrefix(data, []byte("{\\rtf")):
		return s.viaTika(data, ext)
	case ext == ".html" || ext == ".htm" || ext == ".xml" || ext == ".svg":
		s.formats = append(s.formats, strings.TrimPrefix(ext, "."))
		return s.markup(bytes.NewReader(data), nil)
	case utf8.Valid(data) || strings.HasPrefix(http.DetectContentType(data), "text/"):
		s.formats = append(s.formats, "text")
		s.write(strings.ToValidUTF8(string(data), " ") + "\n")
		return nil
	}
	return fmt.Errorf("%w: %s", ErrUnsupported, http.DetectContentType(data))
}

// zip handles Office Open XML packages and plain archives. Sizes come from what is actually read, never from
// headers, and every byte decompressed counts against the ratio budget.
func (s *state) zip(data []byte, depth int) error {
	if depth >= s.l.MaxDepth {
		return fmt.Errorf("%w: archive depth > %d", ErrLimit, s.l.MaxDepth)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("zip: %w", err)
	}
	if s.entries += len(zr.File); s.entries > s.l.MaxEntries {
		return fmt.Errorf("%w: more than %d archive entries", ErrLimit, s.l.MaxEntries)
	}
	office := ""
	for _, f := range zr.File {
		switch f.Name {
		case "word/document.xml":
			office = "docx"
		case "xl/workbook.xml":
			office = "xlsx"
		case "ppt/presentation.xml":
			office = "pptx"
		}
	}
	if office != "" {
		s.formats = append(s.formats, office)
	} else {
		s.formats = append(s.formats, "zip")
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if office != "" && !officeText(office, f.Name) {
			continue
		}
		b, err := s.read(f)
		if err != nil {
			return err
		}
		if office != "" {
			// sharedStrings and worksheets hold cell text and numbers; document/slides hold paragraphs.
			if err := s.markup(bytes.NewReader(b), paragraphEnds); err != nil {
				return fmt.Errorf("%s %s: %w", office, f.Name, err)
			}
		} else if err := s.file(b, f.Name, depth+1); err != nil && !errors.Is(err, ErrUnsupported) {
			return err // one unreadable member (an image) does not hide the rest; a bomb or a cancel stops all
		}
		if s.truncate {
			return nil
		}
	}
	return nil
}

func officeText(kind, name string) bool {
	if !strings.HasSuffix(name, ".xml") {
		return false
	}
	switch kind {
	case "docx":
		return strings.HasPrefix(name, "word/") && !strings.HasPrefix(name, "word/theme/") && name != "word/styles.xml" &&
			name != "word/fontTable.xml" && name != "word/settings.xml" && name != "word/webSettings.xml" && name != "word/numbering.xml"
	case "xlsx":
		return name == "xl/sharedStrings.xml" || strings.HasPrefix(name, "xl/worksheets/sheet") || strings.HasPrefix(name, "xl/comments")
	case "pptx":
		return strings.HasPrefix(name, "ppt/slides/slide") || strings.HasPrefix(name, "ppt/notesSlides/") || strings.HasPrefix(name, "ppt/comments/")
	}
	return false
}

// read decompresses one entry within the budget; nested members are kept in memory, so each is capped at
// MaxBytes too.
func (s *state) read(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("zip %s: %w", f.Name, err)
	}
	defer func() { _ = rc.Close() }()
	limit := min(s.budget, s.l.MaxBytes)
	b, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, fmt.Errorf("zip %s: %w", f.Name, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: %s decompresses past %d× or %d bytes", ErrLimit, f.Name, s.l.MaxRatio, s.l.MaxBytes)
	}
	s.budget -= int64(len(b))
	return b, nil
}

// paragraphEnds: elements after which a line break keeps words of different paragraphs, cells and rows apart.
var paragraphEnds = map[string]bool{"p": true, "tr": true, "row": true, "c": true, "si": true, "br": true, "tab": true, "td": true, "li": true}

// markup collects the character data of an XML/HTML document; ends adds separators after those elements.
// External entities are never resolved (encoding/xml does not), so XXE is not a concern.
func (s *state) markup(r io.Reader, ends map[string]bool) error {
	d := xml.NewDecoder(r)
	d.Strict = false
	d.AutoClose = xml.HTMLAutoClose
	d.Entity = xml.HTMLEntity
	skip := 0 // inside <script>/<style>
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return nil // best effort: keep what was read from malformed markup
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if n := strings.ToLower(t.Name.Local); n == "script" || n == "style" {
				skip++
			}
		case xml.EndElement:
			n := strings.ToLower(t.Name.Local)
			if n == "script" || n == "style" {
				skip = max(0, skip-1)
			}
			if ends == nil || ends[n] {
				if !s.write("\n") {
					return nil
				}
			}
		case xml.CharData:
			if skip == 0 && len(bytes.TrimSpace(t)) > 0 {
				if !s.write(string(t) + " ") {
					return nil
				}
			}
		case xml.Comment:
			// Hidden text in comments is where indirect injections hide (FR-PSEC-2): keep it.
			if !s.write(string(t) + "\n") {
				return nil
			}
		}
	}
}

func (s *state) viaTika(data []byte, ext string) error {
	if s.tika == nil || s.tika.URL == "" {
		return fmt.Errorf("%w: %s needs the Tika service", ErrUnsupported, ext)
	}
	s.formats = append(s.formats, "tika")
	req, err := http.NewRequestWithContext(s.ctx, http.MethodPut, strings.TrimSuffix(s.tika.URL, "/")+"/tika", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/plain")
	resp, err := s.tika.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("tika: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("tika: status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(s.l.MaxText-s.out.Len())+1))
	if err != nil {
		return fmt.Errorf("tika: %w", err)
	}
	s.write(strings.ToValidUTF8(string(b), " "))
	return nil
}
