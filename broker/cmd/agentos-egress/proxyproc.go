package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ghbmrk/agentos/broker/holder"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// modelFlags are the model path's flags, which serve and proxy both take:
// the two processes must agree on the grants (view.go).
type modelFlags struct {
	g           grants
	held        holderDirs
	rulePath    *string
	routingPath *string
	pricesPath  *string
	builderFrom *string
	evalFrom    *string
	agent       *string
	privateOK   *string
}

// declareModelFlags declares the model path's flags on fs; routingDefault
// says what an empty -routing-state means.
func declareModelFlags(fs *flag.FlagSet, routingDefault string) *modelFlags {
	f := &modelFlags{g: grants{}, held: holderDirs{}}
	fs.Var(f.g, "grant", "machine=adapter[,adapter] (repeatable)")
	fs.Var(f.held, "holder", "adapter=dir: the socket directory of the holder that keeps the adapter's API key (repeatable; every adapter or none); the proxy then adds no key itself (ARC-1)")
	f.rulePath = fs.String("rule", "", "routing rule: JSON task class -> routes (P2-7); adoptions may only reorder its routes")
	f.routingPath = fs.String("routing-state", "", "the adopted routing rule, kept across restarts (W3); "+routingDefault)
	f.pricesPath = fs.String("prices", "", "model price table for evaluation routes: JSON \"provider/model\" -> {input, output} per million tokens; empty refuses every evaluation route")
	f.builderFrom = fs.String("builder-from", "", "the owner's agent machine, whose model grants Loop 1's builder machines (lb-) use, always as private data (W3-builder); empty (the default) gives builders no model access")
	f.evalFrom = fs.String("eval-from", "", "the owner's agent machine, whose model grants replay machines use (LOOP-5); empty (the default) gives replay no model access")
	f.agent = agentFlag(fs)
	f.privateOK = fs.String("private-ok", "", "providers the owner allowed for private data, comma-separated (CAP-9)")
	return f
}

// pok is -private-ok as a set.
func (f *modelFlags) pok() map[string]bool {
	pok := map[string]bool{}
	for _, p := range strings.Split(*f.privateOK, ",") {
		if p = strings.TrimSpace(p); p != "" {
			pok[p] = true
		}
	}
	return pok
}

// wire builds the model path over the flags: the router, the evaluation
// route, and the routing socket's state, starting from the adopted rule.
func (f *modelFlags) wire() (*modelWiring, *evalRoute, *routing, error) {
	rule, err := readRule(*f.rulePath)
	if err != nil {
		return nil, nil, nil, err
	}
	pok := f.pok()
	base := rule
	if rule, err = startRule(base, *f.routingPath); err != nil {
		log.Printf("routing: starting from -rule: %v", err)
	}
	mw, err := wireModel(rule, f.g, pok, *f.agent, *f.builderFrom, *f.evalFrom)
	if err != nil {
		return nil, nil, nil, err
	}
	var ev *evalRoute
	if *f.evalFrom != "" {
		ps, err := readPrices(*f.pricesPath)
		if err != nil {
			return nil, nil, nil, err
		}
		ev = &evalRoute{From: *f.evalFrom, Grants: mw.g[*f.evalFrom], PrivateOK: pok, Active: rule, Prices: ps}
	}
	return mw, ev, &routing{base: base, rt: mw.rt, ev: ev, path: *f.routingPath}, nil
}

// defaultProxyRun is the proxy process's socket directory.
const defaultProxyRun = "/run/agentos-proxy"

// proxyCmd is `agentos-egress proxy`: the keyless proxy process (ARC-1,
// CRED-1). It serves the model and routing sockets to the broker, sends
// each call to its adapter's holder, and takes the vault's view from the
// vault process (serve -proxy) on its hand socket. It never opens the
// vault: no vault value and no vault key is ever in its memory.
func proxyCmd(args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	run := fs.String("run", defaultProxyRun, "socket directory (created 0711); serve's -proxy names it")
	brokerUID := fs.Int("broker-uid", -1, "uid of agentosd, the only peer on the model and routing sockets")
	vaultUID := fs.Int("vault-uid", -1, "uid of the vault process (agentos-egress serve), the only peer on the hand socket")
	mf := declareModelFlags(fs, "empty keeps none")
	fs.Parse(args)
	self := os.Getuid()
	if *brokerUID < 0 || *brokerUID == self {
		return errors.New("-broker-uid must name agentosd's own uid, distinct from this process's")
	}
	if *vaultUID < 0 || *vaultUID == self || *vaultUID == *brokerUID {
		return errors.New("-vault-uid must name the vault process's own uid, distinct from this process's and agentosd's: the proxy holds no key")
	}
	mw, ev, ro, err := mf.wire()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	guard, err := netGuard(ctx, &netguard.Sources{}, netWatchEvery)
	if err != nil {
		return err
	}
	pv, err := newProxyView(mw.g, mw.agent, mw.pok, mf.held, guard)
	if err != nil {
		return err
	}
	mw.hook.bind(pv)
	socks := append(modelSockets(pv, mw.rt, ev, ro, *brokerUID),
		socket{holder.HandSocket, *vaultUID, holder.HandHandler(pv, maxView)})
	srvs, err := serveSockets(*run, socks)
	if err != nil {
		return err
	}
	log.Printf("proxy process up, holding no key; sockets in %s", filepath.Clean(*run))
	<-ctx.Done()
	for _, s := range srvs {
		s.Close()
	}
	return nil
}
