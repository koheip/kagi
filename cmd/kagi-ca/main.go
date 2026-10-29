// Command kagi-ca manages the private CA used for kagi mTLS identities.
//
//	kagi-ca init  -dir pki
//	kagi-ca issue -dir pki -kind server -name broker -hosts localhost,127.0.0.1
//	kagi-ca issue -dir pki -kind agent  -name yata  -days 7
//	kagi-ca issue -dir pki -kind admin  -name ops
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/koheip/kagi/internal/pki"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = initCA(os.Args[2:])
	case "issue":
		err = issue(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kagi-ca:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: kagi-ca init|issue [flags]")
	os.Exit(2)
}

func initCA(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", "pki", "output directory")
	days := fs.Int("days", 365, "CA validity in days")
	fs.Parse(args)
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	ca, err := pki.NewCA(time.Duration(*days) * 24 * time.Hour)
	if err != nil {
		return err
	}
	if err := pki.WriteKey(filepath.Join(*dir, "ca.key"), ca.Key); err != nil {
		return err
	}
	if err := pki.WriteCert(filepath.Join(*dir, "ca.crt"), ca.Cert); err != nil {
		return err
	}
	fmt.Printf("CA created in %s (keep ca.key offline in production)\n", *dir)
	return nil
}

func issue(args []string) error {
	fs := flag.NewFlagSet("issue", flag.ExitOnError)
	dir := fs.String("dir", "pki", "CA directory")
	kind := fs.String("kind", "agent", "server | agent | admin")
	name := fs.String("name", "", "identity name ([a-z0-9-])")
	hosts := fs.String("hosts", "localhost,127.0.0.1", "server cert DNS names / IPs")
	days := fs.Int("days", 0, "validity in days (default: server 90, agent 7, admin 30)")
	fs.Parse(args)
	if *name == "" {
		return fmt.Errorf("-name is required")
	}
	k := pki.Kind(*kind)
	d := map[pki.Kind]int{pki.KindServer: 90, pki.KindAgent: 7, pki.KindAdmin: 30}[k]
	if *days > 0 {
		d = *days
	}
	ca, err := pki.LoadCA(filepath.Join(*dir, "ca.crt"), filepath.Join(*dir, "ca.key"))
	if err != nil {
		return err
	}
	cert, key, err := ca.Issue(k, *name, strings.Split(*hosts, ","), time.Duration(d)*24*time.Hour)
	if err != nil {
		return err
	}
	base := filepath.Join(*dir, *name)
	if err := pki.WriteKey(base+".key", key); err != nil {
		return err
	}
	if err := pki.WriteCert(base+".crt", cert); err != nil {
		return err
	}
	fmt.Printf("issued %s certificate for %q -> %s.{crt,key} (valid %d days)\n", k, *name, base, d)
	if k != pki.KindServer {
		fmt.Printf("identity: %s\n", pki.Identity{Kind: k, Name: *name}.URI())
	}
	return nil
}
