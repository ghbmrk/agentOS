package main

// The test binary stands in for llama-server (TestMain dispatches to it
// when started with --model): the same flags, the same three endpoints,
// and switches in the request text for the failures a real one can have.
// It is built in every test run so TestMain compiles with and without the
// infer_llamacpp tag; only the tagged tests start it.

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// fakeDim is the vector length of the fake embedding model.
const fakeDim = 8

// fakeLlamaServer serves on the unix socket named by --host. It records
// its argv and environment beside the socket, for the tests.
func fakeLlamaServer(args []string) {
	var sock string
	embed := false
	for i, a := range args {
		switch a {
		case "--host":
			sock = args[i+1]
		case "--embedding":
			embed = true
		}
	}
	if sock == "" {
		os.Exit(2)
	}
	dir := filepath.Dir(sock)
	os.WriteFile(filepath.Join(dir, "argv"), []byte(strings.Join(args, "\n")), 0o600)
	os.WriteFile(filepath.Join(dir, "env"), []byte(strings.Join(os.Environ(), "\n")), 0o600)
	if strings.Contains(strings.Join(args, " "), "slowstart") {
		time.Sleep(time.Hour)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		os.Exit(2)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"status":"ok"}`)) })
	mux.HandleFunc("/completion", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Prompt string  `json:"prompt"`
			N      int     `json:"n_predict"`
			Temp   float64 `json:"temperature"`
			Cache  bool    `json:"cache_prompt"`
			Stream bool    `json:"stream"`
		}
		if embed || json.NewDecoder(r.Body).Decode(&q) != nil || q.Cache || q.Stream || q.Temp != 0 {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		os.Stderr.WriteString(q.Prompt) // the child's log must never reach the service's
		switch q.Prompt {
		case "crash":
			os.Exit(1)
		case "hang":
			time.Sleep(time.Hour)
		case "status":
			http.Error(w, "boom", http.StatusInternalServerError)
		case "malformed":
			w.Write([]byte(`{"content":`))
		case "nocontent":
			w.Write([]byte(`{}`))
		case "long":
			json.NewEncoder(w).Encode(map[string]string{"content": strings.Repeat("a", 20000)})
		case "huge":
			w.Write([]byte(`{"content":"` + strings.Repeat("a", 2<<20) + `"}`))
		default:
			json.NewEncoder(w).Encode(map[string]any{"content": "reply to " + q.Prompt, "tokens_predicted": q.N})
		}
	})
	mux.HandleFunc("/v1/embeddings", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Input []string `json:"input"`
		}
		if !embed || json.NewDecoder(r.Body).Decode(&q) != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		type item struct {
			Index     int       `json:"index"`
			Embedding []float32 `json:"embedding"`
		}
		var data []item
		for i := len(q.Input) - 1; i >= 0; i-- { // out of order: the adapter places by index
			t := q.Input[i]
			switch t {
			case "crash":
				os.Exit(1)
			case "hang":
				time.Sleep(time.Hour)
			case "short":
				data = append(data, item{i, make([]float32, fakeDim-1)})
				continue
			case "dup": // two vectors for index 0
				data = append(data, item{0, make([]float32, fakeDim)})
				continue
			}
			v := make([]float32, fakeDim)
			for j := range v {
				v[j] = float32(len(t)*10+j) / 1000
			}
			data = append(data, item{i, v})
		}
		json.NewEncoder(w).Encode(map[string]any{"data": data})
	})
	srv := &http.Server{Handler: mux, BaseContext: func(net.Listener) context.Context { return context.Background() }}
	srv.Serve(ln)
}
