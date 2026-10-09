// Command shadow-baseline measures shadow AI use from existing SWG/proxy/firewall/DNS logs before enforcement
// (ticket 03, spec §1.5 baseline). It reads log files (plain or .gz, "-" for stdin), fingerprints each request
// against the AI app catalog, and writes shadow-baseline.json and shadow-baseline.md to -out. Users are HMAC'd with
// TENANT_PEPPER as they are read; no raw user or client IP reaches the output.
//
//	TENANT_PEPPER=... shadow-baseline -format squid -units units.csv -out report/ /var/log/squid/access.log*
package main

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aisec/internal/catalog"
	"aisec/internal/shadow"
)

func main() {
	format := flag.String("format", "", "log format: squid | dns (BIND query log) | jsonl")
	fields := flag.String("fields", "", "jsonl key mapping, e.g. time=ts,user=login,host=hostname,url=url,method=method,user_agent=ua")
	catFile := flag.String("catalog", "", "catalog feed JSON (default: the embedded seed catalog)")
	unitsFile := flag.String("units", "", "CSV of user (or client IP),unit")
	out := flag.String("out", ".", "output directory")
	top := flag.Int("top", 20, "users listed in the report")
	flag.Parse()
	if err := run(*format, *fields, *catFile, *unitsFile, *out, *top, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "shadow-baseline:", err)
		os.Exit(1)
	}
}

func run(format, fields, catFile, unitsFile, out string, top int, files []string) error {
	var p shadow.Parser
	switch format {
	case "squid":
		p = shadow.Squid
	case "dns":
		p = shadow.DNS
	case "jsonl":
		f, err := shadow.ParseJSONFields(fields)
		if err != nil {
			return err
		}
		p = shadow.JSONL(f)
	default:
		return fmt.Errorf("-format %q: want squid, dns or jsonl", format)
	}
	apps := catalog.SeedApps()
	if catFile != "" {
		raw, err := os.ReadFile(catFile)
		if err != nil {
			return err
		}
		f, err := catalog.ParseFeed(raw)
		if err != nil {
			return err
		}
		apps = f.Apps
	}
	units, err := readUnits(unitsFile)
	if err != nil {
		return err
	}
	b, err := shadow.NewBaseline(apps, []byte(os.Getenv("TENANT_PEPPER")), units)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		files = []string{"-"}
	}
	for _, name := range files {
		if err := feed(b, p, name); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	r := b.Report(time.Now(), top)
	js, _ := json.MarshalIndent(r, "", " ")
	if err := os.WriteFile(filepath.Join(out, "shadow-baseline.json"), append(js, '\n'), 0o600); err != nil {
		return err
	}
	md, err := os.OpenFile(filepath.Join(out, "shadow-baseline.md"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := r.Markdown(md); err != nil {
		_ = md.Close()
		return err
	}
	if err := md.Close(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%d lines (%d unreadable), %d AI requests, %d apps, %d days\n", r.Lines, r.Unparsed, r.AIRequests, len(r.Apps), r.DaysCovered)
	if !r.MeetsMinDays {
		fmt.Fprintf(os.Stderr, "warning: logs cover %d days; the baseline needs %d\n", r.DaysCovered, shadow.MinDays)
	}
	return nil
}

func feed(b *shadow.Baseline, p shadow.Parser, name string) error {
	var r io.Reader = os.Stdin
	if name != "-" {
		f, err := os.Open(name)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		r = f
		if strings.HasSuffix(name, ".gz") {
			z, err := gzip.NewReader(f)
			if err != nil {
				return err
			}
			defer func() { _ = z.Close() }()
			r = z
		}
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		b.Line(p, sc.Text())
	}
	return sc.Err()
}

func readUnits(name string) (map[string]string, error) {
	if name == "" {
		return nil, nil
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, row := range rows {
		if len(row) >= 2 {
			m[strings.TrimSpace(row[0])] = strings.TrimSpace(row[1])
		}
	}
	return m, nil
}
