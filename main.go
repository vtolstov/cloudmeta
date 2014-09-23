package main

import (
	"flag"
	"net"
	"strings"
	"syscall"

	"github.com/golang/glog"

	netlink "./netlink"
)

func init() {
	flag.Parse()
}

func main() {
	nl, err := netlink.NewNetlinkSocket(netlink.RTMGRP_LINK)
	if err != nil {
		glog.Error(err.Error())
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		glog.Error(err.Error())
	}

	for _, iface := range ifaces {
		name := iface.Name
		if !strings.HasPrefix(name, "tap") {
			continue
		}
		if _, ok := servers[name[3:]]; !ok {
			s := &Server{name: name[3:]}
			servers[name[3:]] = s
			glog.Infof("%s start serving\n", name[3:])
			go s.Start()
		}
	}

	//	glog.Info("ListenAndServeTCPv4")
	//	go ListenAndServeTCPv4()

	for {
		msgs, err := nl.Receive()
		if err != nil {
			glog.Warningf("nl err: %s\n", err.Error())
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
					glog.Warningf("nl err: %s\n", err.Error())
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
								go s.Start()
								glog.Infof("%s start serving\n", name[3:])
							}
						}
					}
				}
			case syscall.RTM_DELLINK:
				attrs, err := syscall.ParseNetlinkRouteAttr(&msg)
				if err != nil {
					glog.Warningf("nl err: %s\n", err.Error())
					continue
				}
				for _, attr := range attrs {
					switch attr.Attr.Type {
					case syscall.IFLA_IFNAME:
						name := string(attr.Value[:len(attr.Value)-1])
						if strings.HasPrefix(name, "tap") {
							if s, ok := servers[name[3:]]; ok {
								go s.Stop()
								glog.Infof("%s stop serving\n", name[3:])
								delete(servers, name[3:])
							}
						}
					}
				}
			}
		}
	}
}
