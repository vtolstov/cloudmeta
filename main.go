package main

import (
	"flag"
	"io/ioutil"
	"log"
	"fmt"
	"log/syslog"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/alexzorin/libvirt-go.v2"
	"gopkg.in/yaml.v2"
)

func init() {
	flag.Parse()
}

var l *syslog.Writer
var viruri string
var master_iface string = "vlan1001"
var virconn libvirt.VirConnection
var first bool = true

func getVirConn() libvirt.VirConnection {
	if !first {
		if ok, err := virconn.IsAlive(); !ok || err != nil {
			for {
				vc, err := libvirt.NewVirConnection(viruri)
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
			vc, err := libvirt.NewVirConnection(viruri)
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
     var vc libvirt.VirConnection
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

	_, err = os.Stat("/sys/module/xenfs")
	if err == nil {
		viruri = "xen:///"
	} else {
	        viruri = "qemu:///system"
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
		fmt.Printf("callback\n")
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
					default:
					fmt.Printf("%#+v\n", eventDetails)
				}
			}
			f()
			return 0
		},
	)

	fmt.Printf("default event impl\n")
	libvirt.EventRegisterDefaultImpl()

        vc = getVirConn()
        defer vc.UnrefAndCloseConnection()

	fmt.Printf("register event\n")
	callbackId = vc.DomainEventRegister(
		libvirt.VirDomain{},
		libvirt.VIR_DOMAIN_EVENT_ID_LIFECYCLE,
		&callback,
		func() {},

	)
	fmt.Printf("callback id %d\n", callbackId)

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


	fmt.Printf("run event\n")
	for {
	libvirt.EventRunDefaultImpl()
//select{}
}
	// Deregister the event
	if ret := vc.DomainEventDeregister(callbackId); ret < 0 {
		l.Info("Event deregistration failed")
	}
	callbackId = -1 // Don't deregister twice

}
