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

	for {
		//		s.RLock()
		if s.shutdown {
			//		s.RUnlock()
			return
		}
		//s.RUnlock()

		s.ipv6conn.SetReadDeadline(time.Now().Add(time.Second))
		_, cm, src, err := s.ipv6conn.ReadFrom(buffer)
		_ = cm
		if err != nil {
			continue
		}
		fields := strings.Split(src.String(), "%")
		if len(fields) != 2 {
			continue
		}
		device := fields[1]
		dstIP := net.ParseIP(fields[0])
		srcIP := dstIP
		iface, err := net.InterfaceByName(device)
		if err != nil {
			glog.Infof("can't find iface %s: %s\n", device, err.Error())
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			glog.Infof("can't get addresses from %s: %s\n", iface.Name, err.Error())
			continue
		}

		for _, addr := range addrs {
			a := strings.Split(addr.String(), "/")[0]
			ip := net.ParseIP(a)
			if ip == nil {
				continue
			}
			if ip.To4() != nil && strings.HasPrefix(a, "fe80") {
				srcIP = ip
				break
			}
		}
		req := &icmpv6.ICMPv6{}
		err = req.Unmarshal(buffer)
		if err != nil {
			glog.Infof(err.Error())
			continue
		}
		res, err := s.ServeICMPv6(srcIP, req)
		if err != nil {
			glog.Infof(err.Error())
			continue
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
			_, err = s.ipv6conn.WriteTo(buf, &wcm, src)
			if err != nil {
				glog.Infof("%s err: %s", s.name, err.Error())
				continue
			}
		}
	}
}

func (s *Server) ServeICMPv6(src net.IP, req *icmpv6.ICMPv6) ([]*icmpv6.ICMPv6, error) {
	var res []*icmpv6.ICMPv6
	switch req.ICMPType() {
	case ipv6.ICMPTypeRouterSolicitation:
		rs := &icmpv6.RouterSolicitation{}
		rs.Unmarshal(req.Data)
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
