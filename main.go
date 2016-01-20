package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"log/syslog"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"

	"gopkg.in/yaml.v2"
)

func init() {
	flag.Parse()
}

var l *syslog.Writer
var master_iface string = "vlan1001"
var servers *Servers = NewServers()

func main() {
	var err error
	var buf []byte
	var data map[string]string
	l, err = syslog.Dial("", "", syslog.LOG_DAEMON|syslog.LOG_INFO, filepath.Base(os.Args[0]))
	if err != nil {
		log.Fatalf("Failed to connect to syslog: %s\n", err.Error())
		os.Exit(1)
	}
	defer l.Close()

	if buf, err = ioutil.ReadFile("/etc/svirtnet.yml"); err == nil {
		if err = yaml.Unmarshal(buf, &data); err == nil {
			master_iface = data["interface"]
		}
	}

	l.Info("ListenAndServeTCPv4")
	go ListenAndServeTCPv4()

	lnkupdate := make(chan netlink.LinkUpdate)
	lnkdone := make(chan struct{})
	err = netlink.LinkSubscribe(lnkupdate, lnkdone)
	if err != nil {
		l.Err(err.Error())
		os.Exit(1)
	}
	defer close(lnkdone)

	ifaces, err := net.Interfaces()
	if err != nil {
		l.Err(err.Error())
		os.Exit(1)
	}

	for _, iface := range ifaces {
		name := iface.Name
		l.Info("Check iface " + name)
		if !strings.HasPrefix(name, "tap") {
			continue
		}
		servers.Lock()
		if _, ok := servers.Get(name[3:]); !ok {
			s := &Server{name: name[3:]}
			servers.Add(name[3:], s)
			l.Info(name[3:] + " start serving")
			go s.Start()
		}
		servers.Unlock()
	}

	for {
		select {
		case msg := <-lnkupdate:
			switch msg.Header.Type {
			case unix.RTM_NEWLINK:
				if msg.Change == unix.IFF_UP && msg.Flags == unix.IFF_UP {
					fmt.Printf("newlink\n")
					servers.Lock()
					name := msg.Attrs().Name[3:]
					if _, ok := servers.Get(name); !ok {
						s := &Server{name: name}
						servers.Add(name, s)
						l.Info(name + " start serving")
						go s.Start()
					}
					servers.Unlock()
				}
			case unix.RTM_DELLINK:
				if msg.Change == unix.IFF_UP && msg.Flags == 0 & ^unix.IFF_UP {
					fmt.Printf("dellink\n")
					servers.Lock()
					name := msg.Attrs().Name[3:]
					if s, ok := servers.Get(name); ok {
						l.Info(name + " stop serving")
						go s.Stop()
					}
					servers.Del(name)
					servers.Unlock()
				}
			}
		}
	}

}
