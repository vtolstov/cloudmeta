package main

import (
	"net"
	"strings"
	"time"

	"code.google.com/p/go.net/ipv6"
	"github.com/golang/glog"

	"./icmpv6"
)

func (s *Server) ListenAndServeICMPv6() {
	ipAddr := &net.IPAddr{IP: net.IPv6linklocalallrouters, Zone: "tap" + s.name}
	conn, err := net.ListenIP("ip6:58", ipAddr)
	if err != nil {
		glog.Errorf(err.Error())
		return
	}
	if err = bindToDevice(conn, "tap"+s.name); err != nil {
		glog.Errorf(err.Error())
		return
	}
	s.ipv6conn = ipv6.NewPacketConn(conn)

	if err = s.ipv6conn.SetControlMessage(ipv6.FlagDst, true); err != nil {
		glog.Warningf(err.Error())
		return
	}

	buffer := make([]byte, 1500)

	go s.Unsolicitated()

	for {
		//		s.RLock()
		if s.shutdown {
			//		s.RUnlock()
			return
		}
		//s.RUnlock()

		s.ipv6conn.SetReadDeadline(time.Now().Add(time.Second))
		_, _, src, err := s.ipv6conn.ReadFrom(buffer)
		if err != nil {
			continue
		}

		req := &icmpv6.ICMPv6{}
		err = req.Unmarshal(buffer)
		if err != nil {
			glog.Infof(err.Error())
			continue
		}
		if req.Type == uint8(ipv6.ICMPTypeRouterSolicitation) {
			s.sendRA(src)
		}
	}
}

func (s *Server) Unsolicitated() {
	ticker := time.NewTicker(10 * time.Second)
	quit := make(chan struct{})

	time.Sleep(5 * time.Second)
	s.sendRA(nil)

	for {
		select {
		case <-quit:
			ticker.Stop()
			return
		case <-ticker.C:
			if s.shutdown {
				return
			}
			s.sendRA(nil)
			/*
				default:
					if s.shutdown {
						ticker.Stop()
						return
					}
			*/
		}
	}
}

func (s *Server) sendRA(src net.Addr) {
	var srcIP net.IP
	var ipAddr net.Addr

	iface, err := net.InterfaceByName("tap" + s.name)
	if err != nil {
		glog.Infof("can't find iface %s: %s\n", "tap"+s.name, err.Error())
		return
	}
	addrs, err := iface.Addrs()
	if err != nil {
		glog.Infof("can't get addresses from %s: %s\n", iface.Name, err.Error())
		return
	}
	for _, addr := range addrs {
		ip, ipnet, err := net.ParseCIDR(addr.String())
		_ = ipnet
		if err != nil {
			glog.Infof(err.Error())
			continue
		}
		if ip.To4() == nil && strings.HasPrefix(addr.String(), "fe80") {
			srcIP = ip
			if src == nil {
				ipAddr = net.Addr(&net.IPAddr{IP: net.IPv6linklocalallnodes, Zone: "tap" + s.name})
			} else {
				ipAddr = src
			}
			break
		}
	}
	/*
		if src == nil {
			log.Printf("unsolicitated %+v\n", ipAddr)
		} else {
			log.Printf("solicitated %+v\n", ipAddr)
		}
	*/
	if ipAddr == nil || srcIP == nil {
		glog.Infof("ipv6 add missing for tap%s %s", s.name, srcIP)
		return
	}
	res, err := s.ServeICMPv6(srcIP, &icmpv6.ICMPv6{Type: uint8(ipv6.ICMPTypeRouterSolicitation)})
	if err != nil {
		glog.Infof(err.Error())
		return
	}

	for _, msg := range res {
		buf := make([]byte, msg.Len())
		buf, err = msg.Marshal()
		if err != nil {
			glog.Infof("%s err: %s", s.name, err.Error())
			continue
		}

		wcm := ipv6.ControlMessage{HopLimit: 255}
		wcm.Dst = net.IPv6linklocalallnodes
		wcm.IfIndex = iface.Index
		_, err = s.ipv6conn.WriteTo(buf, &wcm, ipAddr)
		if err != nil {
			glog.Infof("%s err: %s", s.name, err.Error())
			continue
		}
	}
}

func (s *Server) ServeICMPv6(src net.IP, req *icmpv6.ICMPv6) ([]*icmpv6.ICMPv6, error) {
	var res []*icmpv6.ICMPv6
	switch req.ICMPType() {
	case ipv6.ICMPTypeRouterSolicitation:
		for _, addr := range s.metadata.Network.IP {
			// TODO fix ipv6 addr
			if addr.Family == "ipv6" && addr.Host == "true" {
				ra := icmpv6.NewRouterAdvertisement(src, net.IPv6linklocalallnodes, addr.Address, addr.Prefix)
				buf, err := ra.Marshal()
				if err != nil {
					return nil, err
				}
				res = append(res, &icmpv6.ICMPv6{Type: ra.Type, Code: ra.Code, Checksum: ra.Checksum, Data: buf[4:]})
			}
		}
	}
	return res, nil
}
