package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"log/syslog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"

	"gopkg.in/yaml.v2"
)

func init() {
	flag.Parse()
}

var (
	l             *syslog.Writer
	master_iface  string   = "vlan1001"
	ipset_support          = true
	servers       *Servers = NewServers()
	flagVersion            = flag.Bool("version", false, "display version string")
	Version                = ""
	BuildTime              = ""
)

func main() {
	var err error
	var buf []byte
	var data map[string]string

	if *flagVersion {
		fmt.Printf("%s build %s\n", Version, BuildTime)
		os.Exit(0)
	}

	l, err = syslog.Dial("", "", syslog.LOG_DAEMON|syslog.LOG_INFO, filepath.Base(os.Args[0]))
	if err != nil {
		log.Fatalf("Failed to connect to syslog: %s\n", err.Error())
		os.Exit(1)
	}
	defer l.Close()

	if buf, err = ioutil.ReadFile("/etc/svirtnet.yml"); err == nil {
		if err = yaml.Unmarshal(buf, &data); err == nil {
			master_iface = data["interface"]
			if val, ok := data["ipset_support"]; ok {
				if val == "false" {
					ipset_support = false
				}
			}
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
			wait := make(chan struct{})
			go func() {
				defer func() {
					if r := recover(); r != nil {
						err, ok := r.(error)
						if !ok {
							err = fmt.Errorf("pkg: %v", r)
						}
						fmt.Printf(err.Error())
					}
				}()
				if err := s.Start(); err != nil {
					panic(err)
				}
				close(wait)
			}()
			<-wait
		}
		servers.Unlock()
	}

	sg := make(chan os.Signal, 1)
	signal.Notify(sg, unix.SIGINT, unix.SIGQUIT, unix.SIGTERM, unix.SIGHUP)

	tk := time.NewTicker(2 * time.Minute)
	defer tk.Stop()
	for {
		select {
		case <-tk.C:
			servers.Lock()
			for _, s := range servers.List() {
				t := time.Now().Add(5 * time.Minute)
				if !s.downtime.IsZero() && t.After(s.downtime) {
					servers.Del(s.name)
				}
			}
			servers.Unlock()
		case signame := <-sg:
			fmt.Println("Got signal:", signame)
			switch signame {
			case syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM:
				servers.Lock()
				for _, s := range servers.List() {
					wait := make(chan struct{})
					go func() {
						defer func() {
							if r := recover(); r != nil {
								err, ok := r.(error)
								if !ok {
									err = fmt.Errorf("pkg: %v", r)
								}
								fmt.Printf(err.Error())
							}
						}()
						if err := s.Stop(false); err != nil {
							panic(err)
						}
						close(wait)
					}()
					<-wait
					servers.Del(s.name)
				}
				servers.Unlock()
				os.Exit(0)
			}
		case msg := <-lnkupdate:
			if !strings.HasPrefix(msg.Attrs().Name, "tap") {
				continue
			}
			switch msg.Header.Type {
			case unix.RTM_NEWLINK:
				if msg.Change == unix.IFF_UP {
					//					fmt.Printf("newlink %#+v\n", msg)
					name := msg.Attrs().Name[3:]
					servers.Lock()
					if s, ok := servers.Get(name); !ok {
						s = &Server{name: name}
						servers.Add(name, s)
						go func() {
							defer func() {
								if r := recover(); r != nil {
									err, ok := r.(error)
									if !ok {
										err = fmt.Errorf("pkg: %v", r)
									}
									fmt.Printf(err.Error())
								}
							}()
							if err := s.Start(); err != nil {
								panic(err)
							}
						}()
					} else {
						go func() {
							defer func() {
								if r := recover(); r != nil {
									err, ok := r.(error)
									if !ok {
										err = fmt.Errorf("pkg: %v", r)
									}
									fmt.Printf(err.Error())
								}
							}()
							if err := s.Start(); err != nil {
								panic(err)
							}
						}()
					}
					servers.Unlock()
				}
			case unix.RTM_DELLINK:
				//				if msg.Change == unix.IFF_UP {
				//				fmt.Printf("dellink %#+v\n", msg)
				servers.Lock()
				name := msg.Attrs().Name[3:]
				if s, ok := servers.Get(name); ok {
					go func() {
						defer func() {
							if r := recover(); r != nil {
								err, ok := r.(error)
								if !ok {
									err = fmt.Errorf("pkg: %v", r)
								}
								fmt.Printf(err.Error())
							}
						}()
						if err := s.Stop(true); err != nil {
							panic(err)
						}
					}()
				}
				servers.Unlock()
				//				}
			}
		}
	}

}
