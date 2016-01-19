package main

import (
	"flag"
	"io/ioutil"
	"log"
	"log/syslog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink/nl"

	"gopkg.in/yaml.v2"
)

func init() {
	flag.Parse()
	servers = make(map[string]*Server, 1024)
}

var l *syslog.Writer
var master_iface string = "vlan1001"

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

	nlink, err := nl.Subscribe(syscall.NETLINK_ROUTE, 1)
	if err != nil {
		l.Err(err.Error())
		os.Exit(1)
	}
	defer nlink.Close()

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
		srvmutex.Lock()
		if _, ok := servers[name[3:]]; !ok {
			s := &Server{name: name[3:]}
			servers[name[3:]] = s
			l.Info(name[3:] + " start serving")
			go s.Start()
		}
		srvmutex.Unlock()
	}

	for {
		msgs, err := nlink.Recieve()
		if err != nil {
			l.Warning("netlink err: " + err.Error())
			continue
		}
	loop:
		for _, msg := range msgs {
			switch msg.Header.Type {
			case syscall.NLMSG_DONE:
				break loop
			case syscall.RTM_NEWLINK:
				attrs, err := syscall.ParseNetlinkRouteAttr(&msg)
				if err != nil {
					l.Warning("netlink err: " + err.Error())
					continue
				}
				for _, attr := range attrs {
					switch attr.Attr.Type {
					case syscall.IFLA_IFNAME:
						name := string(attr.Value[:len(attr.Value)-1])
						if strings.HasPrefix(name, "tap") {
							srvmutex.Lock()
							if s, ok := servers[name[3:]]; !ok {
								s = &Server{name: name[3:]}
								servers[name[3:]] = s
								go s.Start()
								l.Info(name[3:] + " start serving")
								srvmutex.Unlock()
							}
						}
					}
				}
			case syscall.RTM_DELLINK:
				attrs, err := syscall.ParseNetlinkRouteAttr(&msg)
				if err != nil {
					l.Warning("netlink err: " + err.Error())
					continue
				}
				for _, attr := range attrs {
					switch attr.Attr.Type {
					case syscall.IFLA_IFNAME:
						name := string(attr.Value[:len(attr.Value)-1])
						if strings.HasPrefix(name, "tap") {
							srvmutex.Lock()
							if s, ok := servers[name[3:]]; ok {
								go s.Stop()
								l.Info(name[3:] + " stop serving")
								delete(servers, name[3:])
								srvmutex.Unlock()
							}
						}
					}
				}
			}
		}
	}

}
