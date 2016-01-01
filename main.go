package main

import (
	"flag"
	"io/ioutil"
	"log"
	"log/syslog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/vishvananda/netlink/nl"
	"gopkg.in/alexzorin/libvirt-go.v2"
	"gopkg.in/yaml.v2"
)

func init() {
	flag.Parse()
}

var kvm bool
var xen bool
var l *syslog.Writer
var viruri string
var master_iface string = "vlan1001"
var virconn libvirt.VirConnection
var first bool = true

func getVirConn() libvirt.VirConnection {
	if !first {
		if ok, err := virconn.IsAlive(); !ok || err != nil {
			for {
				vc, err := libvirt.NewVirConnectionReadOnly(viruri)
				if err == nil {
					virconn = vc
					return virconn
				}
				l.Info("failed to connect to libvirt:" + err.Error())
				time.Sleep(5 * time.Second)
			}
		}
	} else {
		for {
			vc, err := libvirt.NewVirConnectionReadOnly(viruri)
			if err == nil {
				first = false
				virconn = vc
				return virconn
			}
			l.Info("failed to connect to libvirt:" + err.Error())
			time.Sleep(5 * time.Second)
		}
	}
	return virconn
}

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

	vc := getVirConn()
	defer vc.UnrefAndCloseConnection()

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

	if virdomains, err := vc.ListAllDomains(libvirt.VIR_CONNECT_LIST_DOMAINS_ACTIVE | libvirt.VIR_CONNECT_LIST_DOMAINS_INACTIVE); err == nil {
		for _, d := range virdomains {
			domName, err := d.GetName()
			if err != nil {
				continue
			}
			if _, ok := servers[domName]; !ok {
				servers[domName] = &Server{name: domName}
				l.Info(domName + " start serving")
				go servers[domName].Start()
			}
		}
	}

	l.Info("ListenAndServeTCPv4")
	go ListenAndServeTCPv4()

	callbackId := -1
	defer func() {
		if callbackId >= 0 {
			vc.DomainEventDeregister(callbackId)
		}
		vc.CloseConnection()
	}()

	callback := libvirt.DomainEventCallback(
		func(c *libvirt.VirConnection, d *libvirt.VirDomain, eventDetails interface{}, f func()) int {
			if lifecycleEvent, ok := eventDetails.(libvirt.DomainLifecycleEvent); ok {
				domName, err := d.GetName()
				if err != nil {
					return -1
				}
				switch lifecycleEvent.Event {
				case libvirt.VIR_DOMAIN_EVENT_STARTED:
					if _, ok := servers[domName]; !ok {
						servers[domName] = &Server{name: domName}
						go servers[domName].Start()
						l.Info(domName + " start serving")
						//					} else {
						//						if s.shutdown {
						//							time.Sleep(2 * time.Second)
						//							goto Loop
						//						}
					}
				case libvirt.VIR_DOMAIN_EVENT_STOPPED:
					if s, ok := servers[domName]; ok {
						s.Stop()
						l.Info(domName + " stop serving")
						delete(servers, domName)
					}
				}
			}
			f()
			return 0
		},
	)

	libvirt.EventRegisterDefaultImpl()

	callbackId = vc.DomainEventRegister(
		libvirt.VirDomain{},
		libvirt.VIR_DOMAIN_EVENT_ID_LIFECYCLE,
		&callback,
		func() {},
	)

}
