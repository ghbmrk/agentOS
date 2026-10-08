// Command eval scores recall on the frozen S9 corpus with a chosen embedder.
//
//	eval -corpus ../corpus.json -emb none|hash|file -vectors v.json
//
// "file" reads precomputed vectors keyed by exact text ({"id": "...", "vecs": {text: [..]}}),
// produced by embed_st.py, so any model can be scored through the real index.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/ghbmrk/agentos/broker/recall"
)

type corpus struct {
	Docs []struct{ Ref, Account, Kind, Text string } `json:"docs"`
	Qs   []struct{ ID, Cat, Text, Correct string }   `json:"queries"`
}

type fileEmb struct {
	Name string               `json:"id"`
	Vecs map[string][]float32 `json:"vecs"`
}

func (f *fileEmb) ID() string { return "file/" + f.Name }

func (f *fileEmb) Embed(ts []string) ([][]float32, error) {
	out := make([][]float32, len(ts))
	for i, t := range ts {
		v, ok := f.Vecs[t]
		if !ok {
			return nil, fmt.Errorf("no vector for %q", t)
		}
		out[i] = v
	}
	return out, nil
}

func main() {
	cp := flag.String("corpus", "../corpus.json", "")
	emb := flag.String("emb", "hash", "none|hash|file")
	vp := flag.String("vectors", "", "")
	flag.Parse()
	var c corpus
	b, err := os.ReadFile(*cp)
	check(err)
	check(json.Unmarshal(b, &c))
	var e recall.Embedder
	switch *emb {
	case "hash":
		e = recall.HashEmbedder{}
	case "file":
		var f fileEmb
		b, err := os.ReadFile(*vp)
		check(err)
		check(json.Unmarshal(b, &f))
		e = &f
	}
	opts := []recall.Option{recall.WithEmbedder(embOrNil(*emb, e))}
	k, err := recall.NewKeyer([]byte("s9-spike-synthetic-key-0123456789"))
	check(err)
	opts = append(opts, recall.WithKeyer(k))
	ix, err := recall.Open(recall.NewMemDir(), opts...)
	check(err)
	byRef := map[string]string{}
	now := time.Now()
	for _, d := range c.Docs {
		id, err := ix.Ingest(recall.Item{
			Source:   recall.Source{Kind: d.Kind, Account: d.Account, Ref: d.Ref, Seen: now},
			Label:    recall.Label("private"),
			Text:     d.Text,
			Received: now,
		})
		check(err)
		byRef[id] = d.Ref
	}
	type acc struct {
		r10, mrr float64
		n        int
	}
	cats := map[string]*acc{}
	for _, q := range c.Qs {
		res := ix.Lookup(recall.Query{Text: q.Text, Limit: 10})
		a := cats[q.Cat]
		if a == nil {
			a = &acc{}
			cats[q.Cat] = a
		}
		a.n++
		for rank, r := range res {
			if byRef[r.ID] == q.Correct {
				a.r10++
				a.mrr += 1 / float64(rank+1)
				break
			}
		}
	}
	names := []string{}
	for n := range cats {
		names = append(names, n)
	}
	sort.Strings(names)
	var sr, sm float64
	out := map[string]any{"embedder": *emb}
	for _, n := range names {
		a := cats[n]
		r, m := a.r10/float64(a.n), a.mrr/float64(a.n)
		sr, sm = sr+r, sm+m
		fmt.Printf("%-15s n=%2d recall@10=%.3f mrr=%.3f\n", n, a.n, r, m)
		out[n] = []float64{r, m}
	}
	fmt.Printf("%-15s      recall@10=%.3f mrr=%.3f\n", "OVERALL", sr/float64(len(names)), sm/float64(len(names)))
}

func embOrNil(name string, e recall.Embedder) recall.Embedder {
	if name == "none" {
		return nil
	}
	return e
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
