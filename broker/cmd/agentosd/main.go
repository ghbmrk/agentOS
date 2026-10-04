// Command agentosd runs the AgentOS broker.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ghbmrk/agentos/broker/daemon"
)

func main() {
	var cfg daemon.Config
	flag.StringVar(&cfg.JournalPath, "journal", "/var/lib/agentos/journal.log", "journal file")
	flag.StringVar(&cfg.SocketDir, "sockets", "/run/agentos", "socket directory (created 0700)")
	flag.StringVar(&cfg.OwnerNumber, "owner", "", "owner's phone number, E.164")
	flag.IntVar(&cfg.ModemUID, "modem-uid", -1, "uid of the modem bridge, the only peer allowed on the owner socket")
	flag.Int64Var(&cfg.Admission.CapacityMB, "capacity-mb", 4500, "memory for agent machines, MB")
	flag.Int64Var(&cfg.Admission.HeadroomMB, "headroom-mb", 600, "memory never admitted into, MB")
	flag.Parse()
	if cfg.ModemUID < 0 || cfg.ModemUID == os.Getuid() {
		log.Fatal("-modem-uid must name the modem bridge's own uid, distinct from the broker's")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	d, err := daemon.Run(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("broker up; owner socket %s/%s", cfg.SocketDir, daemon.OwnerSocket)
	d.Wait()
}
