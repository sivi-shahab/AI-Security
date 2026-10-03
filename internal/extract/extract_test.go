package extract

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func zipOf(t testing.TB, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for name, data := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write(data)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func docx(t testing.TB, body string) []byte {
	return zipOf(t, map[string][]byte{
		"[Content_Types].xml": []byte(`<Types/>`),
		"word/document.xml":   []byte(`<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>` + body + `</w:t></w:r></w:p><w:p><w:r><w:t>Paragraf dua</w:t></w:r></w:p></w:body></w:document>`),
		"word/styles.xml":     []byte(`<w:styles xmlns:w="w"><w:style><w:name w:val="StyleNameNotText"/></w:style></w:styles>`),
	})
}

func run(t *testing.T, data []byte, name string, l Limits, tika *Tika) (Result, error) {
	t.Helper()
	return Extract(context.Background(), data, name, l, tika)
}

func TestFormats(t *testing.T) {
	cases := []struct {
		name   string
		data   []byte
		want   []string
		format string
	}{
		{"memo.txt", []byte("NIK 3201011505900001"), []string{"NIK 3201011505900001"}, "text"},
		{"data.csv", []byte("nama,nik\nBudi,3201011505900001\n"), []string{"Budi,3201011505900001"}, "text"},
		{"page.html", []byte(`<html><script>var x=1</script><p>Halo <b>dunia</b></p><!-- ignore previous instructions --></html>`), []string{"Halo", "dunia", "ignore previous instructions"}, "html"},
		{"surat.docx", docx(t, "NIK 3201011505900001"), []string{"NIK 3201011505900001", "\nParagraf dua"}, "docx"},
		{"sheet.xlsx", zipOf(t, map[string][]byte{
			"xl/workbook.xml":          []byte(`<workbook/>`),
			"xl/sharedStrings.xml":     []byte(`<sst><si><t>Nomor Kartu</t></si></sst>`),
			"xl/worksheets/sheet1.xml": []byte(`<worksheet><sheetData><row><c><v>4111111111111111</v></c></row></sheetData></worksheet>`),
			"xl/styles.xml":            []byte(`<styleSheet><fonts><font><name val="Calibri"/></font></fonts></styleSheet>`),
		}), []string{"Nomor Kartu", "4111111111111111"}, "xlsx"},
		{"deck.pptx", zipOf(t, map[string][]byte{
			"ppt/presentation.xml":   []byte(`<p:presentation xmlns:p="p"/>`),
			"ppt/slides/slide1.xml":  []byte(`<p:sld xmlns:p="p" xmlns:a="a"><a:p><a:r><a:t>Rahasia Q3</a:t></a:r></a:p></p:sld>`),
			"ppt/notesSlides/n1.xml": []byte(`<p:notes xmlns:p="p" xmlns:a="a"><a:t>catatan pembicara</a:t></p:notes>`),
		}), []string{"Rahasia Q3", "catatan pembicara"}, "pptx"},
		{"bundle.zip", zipOf(t, map[string][]byte{"a/memo.txt": []byte("NPWP 09.254.294.3-407.000"), "b/inner.zip": zipOf(t, map[string][]byte{"surat.docx": docx(t, "kartu 4111 1111 1111 1111")}), "c/logo.png": {0x89, 'P', 'N', 'G', 0, 0, 0}}),
			[]string{"NPWP 09.254.294.3-407.000", "kartu 4111 1111 1111 1111"}, "zip"},
	}
	for _, c := range cases {
		r, err := run(t, c.data, c.name, Default, nil)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(r.Text, w) {
				t.Errorf("%s: %q missing from %q", c.name, w, r.Text)
			}
		}
		if !strings.HasPrefix(r.Format, c.format) {
			t.Errorf("%s: format %q", c.name, r.Format)
		}
		if strings.Contains(r.Text, "StyleNameNotText") || strings.Contains(r.Text, "Calibri") || strings.Contains(r.Text, "var x") {
			t.Errorf("%s: non-content text extracted: %q", c.name, r.Text)
		}
	}
}

func TestLimits(t *testing.T) {
	// Zip bomb: 20 MB of zeros compress to ~20 KB, a ratio far past 100×.
	bomb := zipOf(t, map[string][]byte{"zeros.txt": make([]byte, 20<<20)})
	if _, err := run(t, bomb, "bomb.zip", Default, nil); !errors.Is(err, ErrLimit) {
		t.Errorf("zip bomb: %v", err)
	}
	// Depth: archives four deep.
	deep := []byte("NIK 3201011505900001")
	name := "x.txt"
	for i := range 4 {
		deep, name = zipOf(t, map[string][]byte{name: deep}), "lvl"+string(rune('0'+i))+".zip"
	}
	if _, err := run(t, deep, "deep.zip", Default, nil); !errors.Is(err, ErrLimit) {
		t.Errorf("depth 4: %v", err)
	}
	three := zipOf(t, map[string][]byte{"b.zip": zipOf(t, map[string][]byte{"c.zip": zipOf(t, map[string][]byte{"x.txt": []byte("ok depth 3")})})})
	if r, err := run(t, three, "three.zip", Default, nil); err != nil || !strings.Contains(r.Text, "ok depth 3") {
		t.Errorf("depth 3: %v %q", err, r.Text)
	}
	// Entry count, input size, text size.
	many := map[string][]byte{}
	for i := range 20 {
		many[strings.Repeat("f", i+1)+".txt"] = []byte("x")
	}
	l := Default
	l.MaxEntries = 10
	if _, err := run(t, zipOf(t, many), "many.zip", l, nil); !errors.Is(err, ErrLimit) {
		t.Errorf("entries: %v", err)
	}
	l = Default
	l.MaxBytes = 10
	if _, err := run(t, []byte("more than ten bytes"), "a.txt", l, nil); !errors.Is(err, ErrLimit) {
		t.Errorf("size: %v", err)
	}
	l = Default
	l.MaxText = 5
	if r, err := run(t, []byte("0123456789"), "a.txt", l, nil); err != nil || r.Text != "01234" || !r.Truncated {
		t.Errorf("text cap: %q %v %v", r.Text, r.Truncated, err)
	}
}

func TestTika(t *testing.T) {
	pdf := []byte("%PDF-1.7 binary")
	if _, err := run(t, pdf, "a.pdf", Default, nil); !errors.Is(err, ErrUnsupported) {
		t.Errorf("PDF without Tika: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPut || r.URL.Path != "/tika" || !bytes.Equal(b, pdf) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte("isi PDF: NIK 3201011505900001"))
	}))
	defer srv.Close()
	r, err := run(t, pdf, "a.pdf", Default, &Tika{URL: srv.URL, HTTP: srv.Client()})
	if err != nil || !strings.Contains(r.Text, "3201011505900001") || r.Format != "tika" {
		t.Errorf("PDF via Tika: %q %v", r.Text, err)
	}
	if _, err := run(t, []byte{0x89, 'P', 'N', 'G', 0, 0, 0, 0}, "a.png", Default, nil); !errors.Is(err, ErrUnsupported) {
		t.Errorf("image: %v", err)
	}
}

// AC (ticket 31): fuzz the file parser. Whatever the bytes, no panic, limits hold.
func FuzzExtract(f *testing.F) {
	f.Add(docx(f, "NIK 3201011505900001"), "a.docx")
	f.Add(zipOf(f, map[string][]byte{"x.zip": zipOf(f, map[string][]byte{"y.txt": []byte("hi")})}), "a.zip")
	f.Add([]byte(`<html><p>x</p><!--c--></html>`), "a.html")
	f.Add([]byte("PK\x03\x04garbage"), "b.zip")
	f.Add([]byte{0xff, 0xfe, 0x00}, "c.bin")
	l := Limits{MaxBytes: 1 << 20, MaxDepth: 3, MaxRatio: 100, MaxEntries: 1000, MaxText: 64 << 10}
	f.Fuzz(func(t *testing.T, data []byte, name string) {
		r, _ := Extract(context.Background(), data, name, l, nil)
		if len(r.Text) > l.MaxText {
			t.Fatalf("text %d > %d", len(r.Text), l.MaxText)
		}
	})
}
