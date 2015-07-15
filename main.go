package main

import (
	"flag"
	"io/ioutil"
	"log"
	"log/syslog"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/vtolstov/svirtnet/internal/github.com/alexzorin/libvirt-go"
	"github.com/vtolstov/svirtnet/internal/github.com/vishvananda/netlink/nl"
	"github.com/vtolstov/svirtnet/internal/gopkg.in/yaml.v2"
)

func init() {
	flag.Parse()
}

var kvm bool
var xen bool
var l *syslog.Writer
var viruri string
var master_iface string = "1001"
var virconn libvirt.VirConnection
var first bool = true

func getVirConn() libvirt.VirConnection {
	if first {
		first = false
		if ok, err := virconn.IsAlive(); !ok || err != nil {
			for {
				vc, err := libvirt.NewVirConnectionReadOnly(viruri)
				if err == nil {
					virconn = vc
					return vc
				}
				l.Info("failed to connect to libvirt:" + err.Error())
				time.Sleep(5 * time.Second)
			}
		}
	}
	return virconn
}

func main() {
	var err error
	var buf []byte
	var data map[string]string
	l, err = syslog.Dial("", "", syslog.LOG_DAEMON|syslog.LOG_INFO, "svirtnet")
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

	/*
		_, err = os.Stat("/srv/iso")
		if err != nil {
			err = os.MkdirAll("/srv/iso", 0770)
			if err != nil {
				l.Info(fmt.Sprintf("Failed to create dir: %s\n", err.Error()))
				os.Exit(1)
			}
		}
	*/

	nlink, err := nl.Subscribe(syscall.NETLINK_ROUTE, 1)
	if err != nil {
		l.Err(err.Error())
		os.Exit(1)
	}
	defer nlink.Close()

	_, err = os.Stat("/sys/module/kvm")
	if err == nil {
		kvm = true
	}
	_, err = os.Stat("/sys/module/xenfs")
	if err == nil {
		xen = true
	}

	if !kvm && !xen {
		l.Err("hypervisor not detected")
		os.Exit(1)
	}

	if kvm {
		viruri = "qemu:///system"
	}

	if xen {
		viruri = "xen:///"
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		l.Err(err.Error())
		os.Exit(1)
	}

	for _, iface := range ifaces {
		name := iface.Name
		l.Info("Check iface " + name)
		if !strings.HasPrefix(name, "tap") && !strings.HasPrefix(name, "vif") {
			continue
		}
		if _, ok := servers[name[3:]]; !ok {
			s := &Server{name: name[3:]}
			servers[name[3:]] = s
			l.Info(name[3:] + " start serving")
			go s.Start()
		}
	}

	l.Info("ListenAndServeTCPv4")
	go ListenAndServeTCPv4()

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
						if strings.HasPrefix(name, "tap") || strings.HasPrefix(name, "vif") {
							if _, ok := servers[name[3:]]; !ok {
								s := &Server{name: name[3:]}
								servers[name[3:]] = s
								go s.Start()
								l.Info(name[3:] + " start serving")
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
						if strings.HasPrefix(name, "tap") || strings.HasPrefix(name, "vif") {
							if s, ok := servers[name[3:]]; ok {
								go s.Stop()
								l.Info(name[3:] + " stop serving")
								delete(servers, name[3:])
							}
						}
					}
				}
			}
		}
	}
}
