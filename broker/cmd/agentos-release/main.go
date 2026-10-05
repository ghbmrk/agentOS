// Command agentos-release is the maintainers' release signing tool (UPD-2,
// UPD-8). Root and targets keys stay on offline machines: each holder runs
// `sign` against the staged files, carried between machines on a drive,
// and `publish` refuses anything below a role's threshold. Snapshot and
// timestamp keys are online keys for a scheduled `refresh`.
//
//	agentos-release keygen BASE             write BASE.key (0600) and BASE.pub
//	agentos-release init -repo D -root a.pub,b.pub,c.pub -root-threshold 2 \
//	    -targets ... -targets-threshold 2 -snapshot s.pub -timestamp t.pub
//	agentos-release add-release -repo D -version N -usr-root-hash H \
//	    -file boot/N/entry.conf=./entry.conf ... [-channel fast] [-security]
//	agentos-release rotate -repo D -role targets -add new.pub -remove lost.pub [-threshold N]
//	agentos-release sign -repo D -role root|targets -key k.key
//	agentos-release publish -repo D -snapshot-key s.key -timestamp-key t.key
//	agentos-release refresh -repo D -snapshot-key s.key -timestamp-key t.key
//	agentos-release verify -repo D -root 1.root.json -installed N [-offline] [-channel fast]
//
// The repository directory is what mirrors and drives carry (DEP-4).
package main

import (
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/ghbmrk/agentos/broker/update"
)

func main() {
	log.SetFlags(0)
	if err := run(os.Args[1:], os.Stdout); err != nil {
		log.Fatal("agentos-release: ", err)
	}
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func pubs(list string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, p := range strings.Split(list, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		k, err := update.LoadPublicKey(p)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

func run(args []string, out io.Writer) error {
	if len(args) < 1 {
		return errors.New("usage: agentos-release keygen|init|add-release|rotate|sign|publish|refresh|verify [flags]")
	}
	cmd, args := args[0], args[1:]
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(out)
	repo := fs.String("repo", "", "repository directory")
	r := func() update.Repo { return update.Repo{Dir: *repo} }
	needRepo := func() error {
		if *repo == "" {
			return errors.New("-repo is required")
		}
		return nil
	}
	switch cmd {
	case "keygen":
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return errors.New("usage: keygen BASE")
		}
		pub, err := update.Keygen(fs.Arg(0))
		if err != nil {
			return err
		}
		id, _ := update.KeyID(pub)
		fmt.Fprintf(out, "key id %s\n", id)
		return nil

	case "init":
		var root, targets, snap, ts string
		var rt, tt int
		fs.StringVar(&root, "root", "", "root public keys, comma-separated")
		fs.StringVar(&targets, "targets", "", "targets public keys, comma-separated")
		fs.StringVar(&snap, "snapshot", "", "snapshot public key")
		fs.StringVar(&ts, "timestamp", "", "timestamp public key")
		fs.IntVar(&rt, "root-threshold", 2, "root signatures required")
		fs.IntVar(&tt, "targets-threshold", 2, "targets signatures required")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if err := needRepo(); err != nil {
			return err
		}
		var cfg update.RootConfig
		var err error
		for _, x := range []struct {
			dst  *[]ed25519.PublicKey
			list string
		}{{&cfg.Root, root}, {&cfg.Targets, targets}, {&cfg.Snapshot, snap}, {&cfg.Timestamp, ts}} {
			if *x.dst, err = pubs(x.list); err != nil {
				return err
			}
		}
		cfg.RootThreshold, cfg.TargetsThreshold = rt, tt
		if _, err := update.Init(*repo, cfg); err != nil {
			return err
		}
		fmt.Fprintln(out, "staged root v1 and targets v1; sign both, then publish")
		return nil

	case "add-release":
		var rel update.Manifest
		var files multi
		fs.Int64Var(&rel.Version, "version", 0, "release version")
		fs.StringVar(&rel.Channel, "channel", update.ChannelStable, "stable or fast")
		fs.BoolVar(&rel.Security, "security", false, "security fix")
		fs.StringVar(&rel.UsrRootHash, "usr-root-hash", "", "dm-verity root hash of /usr")
		fs.Var(&files, "file", "TARGET=LOCAL, repeatable; TARGET alone reuses a published target")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if err := needRepo(); err != nil {
			return err
		}
		m := map[string]string{}
		for _, f := range files {
			t, l, ok := strings.Cut(f, "=")
			rel.Files = append(rel.Files, t)
			if ok {
				m[t] = l
			}
		}
		if err := r().AddRelease(rel, m); err != nil {
			return err
		}
		fmt.Fprintf(out, "staged release %d; sign targets, then publish\n", rel.Version)
		return nil

	case "rotate":
		var role, add, remove string
		var threshold int
		fs.StringVar(&role, "role", "", "root, targets, snapshot or timestamp")
		fs.StringVar(&add, "add", "", "public keys to add")
		fs.StringVar(&remove, "remove", "", "public keys to revoke")
		fs.IntVar(&threshold, "threshold", 0, "new threshold (0 keeps it)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if err := needRepo(); err != nil {
			return err
		}
		a, err := pubs(add)
		if err != nil {
			return err
		}
		d, err := pubs(remove)
		if err != nil {
			return err
		}
		if err := r().Rotate(role, a, d, threshold); err != nil {
			return err
		}
		fmt.Fprintln(out, "staged the next root; it needs the old and the new root thresholds")
		return nil

	case "sign":
		var role, key string
		fs.StringVar(&role, "role", "", "root or targets")
		fs.StringVar(&key, "key", "", "private key file")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if err := needRepo(); err != nil {
			return err
		}
		k, err := update.LoadPrivateKey(key)
		if err != nil {
			return err
		}
		if err := r().Sign(role, k); err != nil {
			return err
		}
		fmt.Fprintf(out, "signed staged %s\n", role)
		return nil

	case "publish", "refresh":
		var sk, tk string
		fs.StringVar(&sk, "snapshot-key", "", "snapshot private key file")
		fs.StringVar(&tk, "timestamp-key", "", "timestamp private key file")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if err := needRepo(); err != nil {
			return err
		}
		s, err := update.LoadPrivateKey(sk)
		if err != nil {
			return err
		}
		t, err := update.LoadPrivateKey(tk)
		if err != nil {
			return err
		}
		if cmd == "publish" {
			err = r().Publish(s, t)
		} else {
			err = r().Refresh(s, t)
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "%sed\n", cmd)
		return nil

	case "verify":
		var root, channel string
		var installed int64
		var offline bool
		fs.StringVar(&root, "root", "", "trusted root metadata, as shipped in the image")
		fs.Int64Var(&installed, "installed", 0, "installed release version")
		fs.BoolVar(&offline, "offline", false, "check as a drive install (no expiry)")
		fs.StringVar(&channel, "channel", update.ChannelStable, "stable or fast")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if err := needRepo(); err != nil {
			return err
		}
		b, err := os.ReadFile(root)
		if err != nil {
			return err
		}
		tmp, err := os.MkdirTemp("", "agentos-verify-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		st, err := update.InitStore(tmp+"/s", b, installed)
		if err != nil {
			return err
		}
		res, err := st.Check(update.DirSource(*repo), update.Options{Offline: offline, Channel: channel})
		if err != nil {
			return err
		}
		if res.Release == nil {
			fmt.Fprintln(out, "verified; no release newer than", installed)
			return nil
		}
		rel := res.Release.Manifest()
		fmt.Fprintf(out, "verified release %d (%s, security=%v) usr root hash %s\n", rel.Version, rel.Channel, rel.Security, rel.UsrRootHash)
		for _, f := range res.Release.Files() {
			fmt.Fprintf(out, "  %s %d sha256:%s\n", f.Path, f.Length, f.SHA256)
		}
		return nil
	}
	return fmt.Errorf("unknown command %q", cmd)
}
