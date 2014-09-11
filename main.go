package main

import (
	"log"
	"net"
	"os"
	"strings"
	"syscall"

	netlink "./netlink"
)

func main() {
	nl, err := netlink.NewNetlinkSocket(netlink.RTMGRP_LINK)
	if err != nil {
		log.Printf(err.Error())
		os.Exit(1)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf(err.Error())
		os.Exit(1)
	}

	for _, iface := range ifaces {
		name := iface.Name
		if !strings.HasPrefix(name, "tap") {
			continue
		}
		if _, ok := servers[name[3:]]; !ok {
			s := &Server{name: name[3:]}
			servers[name[3:]] = s
			log.Printf("start serving %s\n", name[3:])
			go func() {
				err := s.Start()
				if err != nil {
					log.Printf("err %s\n", err.Error())
				}
			}()
		}
	}

	for {
		msgs, err := nl.Receive()
		if err != nil {
			log.Printf("nl err: %s\n", err.Error())
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
					log.Printf("nl err: %s\n", err.Error())
					continue
				}
				for _, attr := range attrs {
					switch attr.Attr.Type {
					case syscall.IFLA_IFNAME:
						name := string(attr.Value[:len(attr.Value)-1])
						if strings.HasPrefix(name, "tap") {
							if _, ok := servers[name[3:]]; !ok {
								s := &Server{name: name[3:]}
								servers[name[3:]] = s
								err = nil
								go func(err error) error {
									err = s.Start()
									return err
								}(err)
								if err == nil {
									log.Printf("start serving %s\n", name[3:])
								} else {
									log.Printf("failed serving %s %s\n", name[3:], err.Error())
								}
							}
						}
					}
				}
			case syscall.RTM_DELLINK:
				attrs, err := syscall.ParseNetlinkRouteAttr(&msg)
				if err != nil {
					log.Printf("nl err: %s\n", err.Error())
					continue
				}
				for _, attr := range attrs {
					switch attr.Attr.Type {
					case syscall.IFLA_IFNAME:
						name := string(attr.Value[:len(attr.Value)-1])
						if strings.HasPrefix(name, "tap") {
							if s, ok := servers[name[3:]]; ok {
								log.Printf("stop serving %s\n", name[3:])
								err = nil
								go func(err error) error {
									err = s.Stop()
									return err
								}(err)
								if err == nil {
									log.Printf("stop serving %s\n", name[3:])
								} else {
									log.Printf("failed serving %s %s\n", name[3:], err.Error())
								}
								delete(servers, name[3:])
							}
						}
					}
				}
			}
		}
	}
}
