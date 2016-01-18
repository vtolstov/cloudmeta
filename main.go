package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
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
		vc := getVirConn()
		if callbackId >= 0 {
			vc.DomainEventDeregister(callbackId)
		}
		fmt.Printf("close libvirt conn\n")
		//	vc.CloseConnection()
		vc.UnrefAndCloseConnection()
	}()

	callback := libvirt.DomainEventCallback(
		func(c *libvirt.VirConnection, d *libvirt.VirDomain, eventDetails interface{}, f func()) int {
			if d == nil || eventDetails == nil || c == nil {
				return -1
			}

			if lifecycleEvent, ok := eventDetails.(libvirt.DomainLifecycleEvent); ok {
				switch lifecycleEvent.Event {
				case libvirt.VIR_DOMAIN_EVENT_STARTED:
					domName, err := d.GetName()
					if err != nil {
						l.Info("failed to get domain name")
						return -1
					}
					srvmutex.Lock()
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
					srvmutex.Unlock()
				case libvirt.VIR_DOMAIN_EVENT_STOPPED, libvirt.VIR_DOMAIN_EVENT_SHUTDOWN, libvirt.VIR_DOMAIN_EVENT_CRASHED:
					domName, err := d.GetName()
					if err != nil {
						l.Info("failed to get domain name")
						return -1
					}
					srvmutex.Lock()
					if s, ok := servers[domName]; ok {
						s.Stop()
						l.Info(domName + " stop serving")
						delete(servers, domName)
					}
					srvmutex.Unlock()
				default:
					fmt.Printf("%#+v\n", eventDetails)
				}
			}
			//f()
			return 0
		},
	)

	libvirt.EventRegisterDefaultImpl()

	vc = getVirConn()
	//	defer vc.UnrefAndCloseConnection()

	callbackId = vc.DomainEventRegister(
		libvirt.VirDomain{},
		libvirt.VIR_DOMAIN_EVENT_ID_LIFECYCLE,
		&callback,
		func() {
			fmt.Sprintf("catch")
		},
	)
	if callbackId < 0 {
		log.Fatalf("libvirt event registration failed")
		os.Exit(1)
	}

	if virdomains, err := vc.ListAllDomains(libvirt.VIR_CONNECT_LIST_DOMAINS_ACTIVE | libvirt.VIR_CONNECT_LIST_DOMAINS_INACTIVE); err == nil {
		for _, d := range virdomains {
			domName, err := d.GetName()
			if err != nil {
				continue
			}
			srvmutex.Lock()
			if _, ok := servers[domName]; !ok {
				servers[domName] = &Server{name: domName}
				l.Info(domName + " start serving")
				go servers[domName].Start()
			}
			srvmutex.Unlock()
		}
	}

	for {
		libvirt.EventRunDefaultImpl()
	}

	// Deregister the event
	if ret := vc.DomainEventDeregister(callbackId); ret < 0 {
		l.Info("Event deregistration failed")
	}
	callbackId = -1 // Don't deregister twice

}
