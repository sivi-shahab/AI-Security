// Command evalcorpus manages the frozen detector eval sets (ticket 04, spec §9.3–9.4).
//
//	evalcorpus freeze -dir data/eval/v2 -seed 2  # generate synthetic files, hash everything, write MANIFEST.json
//	evalcorpus score  -dir data/eval/v1          # verify hashes, score detection L1, print Markdown
//	evalcorpus sheet  -dir data/eval/v1 > s.jsonl  # blind sheet for annotators: id + text, no labels
//	evalcorpus kappa  a.jsonl b.jsonl            # Cohen's κ per question; exit 1 below 0.8
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"aisec/internal/detect"
	"aisec/internal/evalcorpus"
)

// MinKappa is the inter-annotator agreement the spec requires (§9.3).
const MinKappa = 0.8

// public lists the open-licensed sets a version may include; their files are fetched once and frozen with it.
var public = map[string]evalcorpus.File{
	"public-deepset-test.jsonl": {Kind: "mixed", Source: "https://huggingface.co/datasets/deepset/prompt-injections (split test)",
		License: "Apache-2.0", Upstream: "4f61ecb038e9c3fb77e21034b22511b523772cdd"},
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	dir := fs.String("dir", "data/eval/v1", "eval set directory")
	seed := fs.Uint64("seed", 1, "generator seed (freeze)")
	threshold := fs.Float64("threshold", 0.8, "injection score counted as flagged (score)")
	_ = fs.Parse(os.Args[2:])
	var err error
	switch os.Args[1] {
	case "freeze":
		err = freeze(*dir, *seed)
	case "score":
		var ss []evalcorpus.Sample
		if _, ss, err = evalcorpus.Load(*dir); err == nil {
			err = evalcorpus.Score(ss, detect.Scan, *threshold).Markdown(os.Stdout)
		}
	case "sheet":
		var ss []evalcorpus.Sample
		if _, ss, err = evalcorpus.Load(*dir); err == nil {
			enc := json.NewEncoder(os.Stdout)
			for _, s := range ss {
				if err = enc.Encode(map[string]string{"id": s.ID, "text": s.Text}); err != nil {
					break
				}
			}
		}
	case "kappa":
		err = kappa(fs.Args())
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "evalcorpus:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: evalcorpus freeze|score|sheet|kappa [flags]")
	os.Exit(2)
}

func freeze(dir string, seed uint64) error {
	if _, err := os.Stat(filepath.Join(dir, "MANIFEST.json")); err == nil {
		return fmt.Errorf("%s is frozen; a new eval set goes in a new directory", dir)
	}
	pii, inj, ben := evalcorpus.Synthetic(seed)
	m := evalcorpus.Manifest{Version: filepath.Base(dir), Frozen: time.Now().Format(time.DateOnly),
		Note: "Holdout. Never train or tune on it; a changed file fails the hash check (evalcorpus.Load)."}
	for _, f := range []struct {
		name, kind string
		ss         []evalcorpus.Sample
	}{{"synthetic-pii.jsonl", "pii", pii}, {"synthetic-injection.jsonl", "injection", inj}, {"synthetic-benign.jsonl", "benign", ben}} {
		raw := evalcorpus.Encode(f.ss)
		if err := os.WriteFile(filepath.Join(dir, f.name), raw, 0o644); err != nil {
			return err
		}
		m.Files = append(m.Files, evalcorpus.File{Name: f.name, Kind: f.kind, Samples: len(f.ss), SHA256: evalcorpus.Hash(raw),
			Source: "synthetic: " + evalcorpus.GeneratorVersion, License: "internal", Seed: seed})
	}
	for name, f := range public {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		ss, err := evalcorpus.Decode(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		f.Name, f.Samples, f.SHA256 = name, len(ss), evalcorpus.Hash(raw)
		m.Files = append(m.Files, f)
	}
	js, _ := json.MarshalIndent(m, "", " ")
	return os.WriteFile(filepath.Join(dir, "MANIFEST.json"), append(js, '\n'), 0o644)
}

func kappa(files []string) error {
	if len(files) != 2 {
		return fmt.Errorf("kappa needs two annotation files")
	}
	var anns [2]map[string]evalcorpus.Annotation
	for i, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		if anns[i], err = evalcorpus.DecodeAnnotations(raw); err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
	}
	ag := evalcorpus.Agree(anns[0], anns[1])
	fmt.Printf("| Pertanyaan | κ |\n|---|---:|\n")
	for _, q := range slices.Sorted(maps.Keys(ag.Kappa)) {
		fmt.Printf("| %s | %.3f |\n", q, ag.Kappa[q])
	}
	fmt.Printf("\n%d sampel dilabel kedua annotator; κ minimum %.3f (target %.1f).\n", ag.Items, ag.Min, MinKappa)
	if ag.Min < MinKappa {
		return fmt.Errorf("agreement below %.1f: adjudicate and revise the guideline", MinKappa)
	}
	return nil
}
