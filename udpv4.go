package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"code.google.com/p/go.net/ipv4"
	"github.com/golang/glog"
	"github.com/vtolstov/ogo/protocol/util"

	"./dhcpv4"
	pipv4 "./ipv4"
	"./udp"
)

func (s *Server) ListenAndServeUDPv4() {
	ipAddr := &net.IPAddr{IP: net.IPv4zero}
	conn, err := net.ListenIP("ip4:udp", ipAddr)
	if err != nil {
		glog.Errorf(err.Error())
		return
	}
	if err = bindToDevice(conn, "tap"+s.name); err != nil {
		glog.Errorf(err.Error())
		return
	}

	s.ipv4conn, err = ipv4.NewRawConn(conn)
	if err != nil {
		glog.Errorf(err.Error())
		return
	}

	if err = s.ipv4conn.SetControlMessage(ipv4.FlagDst, true); err != nil {
		glog.Warningf(err.Error())
		return
	}

	buffer := make([]byte, 1500)

	var gw net.IP
	for _, addr := range s.metadata.Network.IP {
		if addr.Family == "ipv4" && addr.Host == "true" && addr.Gateway == "true" {
			gw = net.ParseIP(addr.Address)
		}
	}
	iface, err := net.InterfaceByName("tap" + s.name)
	if err != nil {
		glog.Errorf(err.Error())
	}

	for {
		//		s.RLock()
		if s.shutdown {
			//		s.RUnlock()
			return
		}
		//s.RUnlock()

		s.ipv4conn.SetReadDeadline(time.Now().Add(time.Second))

		hdr, payload, _, err := s.ipv4conn.ReadFrom(buffer)

		if err != nil {
			switch v := err.(type) {
			case *net.OpError:
				if v.Timeout() {
					continue
				}
			case *net.AddrError:
				if v.Timeout() {
					continue
				}
			case *net.UnknownNetworkError:
				if v.Timeout() {
					continue
				}
			default:
				glog.Warningf(err.Error())
				return
			}
		}

		if hdr == nil || hdr.Protocol != int(pipv4.Type_UDP) {
			continue
		}

		req := &udp.UDP{}
		err = req.Unmarshal(payload)
		if err != nil {
			glog.Warningf(err.Error())
			continue
		}

		res, err := s.ServeUDPv4(req)

		if err != nil {
			glog.Infof("Error Serving UDPv4: %s\n", err)
			continue
		}
		if res == nil {
			continue
		}
		var buf []byte
		res.Checksum = 0
		if buf, err = res.Marshal(); err != nil {
			glog.Warningf(err.Error())
			continue
		}

		res.Checksum = util.Checksum(append(udp.UDPv4PseudoHeader(gw, net.IPv4bcast, pipv4.Type_UDP, res.Length+1), buf...))

		if buf, err = res.Marshal(); err != nil {
			glog.Warningf(err.Error())
			continue
		}
		wcm := ipv4.ControlMessage{TTL: 255}
		wcm.Dst = net.IPv4bcast.To4()
		wcm.Src = gw.To4()
		wcm.IfIndex = iface.Index
		err = s.ipv4conn.WriteTo(&ipv4.Header{Len: 20, TOS: hdr.TOS, TotalLen: 20 + int(res.Length), FragOff: 0, TTL: 255, Protocol: int(pipv4.Type_UDP), Src: gw.To4(), Dst: wcm.Dst.To4()}, buf, &wcm)
		if err != nil {
			glog.Infof("Error Writing: %s\n", err.Error())
		}
	}
}

func (s *Server) ServeUDPv4(req *udp.UDP) (*udp.UDP, error) {
	dhcpreq := &dhcpv4.DHCP{}
	if err := dhcpreq.Unmarshal(req.Data); err != nil {
		return nil, err
	}
	dhcpres := &dhcpv4.DHCP{}

	glog.Infof("%s dhcpv4 req: %+v\n", s.name, dhcpreq)

	udpres := &udp.UDP{}
	udpres.Src = req.Dst
	udpres.Dst = req.Src

	leaseTime := 6000
	var ip net.IP
	var gw net.IP
	var mac net.HardwareAddr
	var ipnet *net.IPNet
	var err error
	mac = dhcpreq.ClientHWAddr

	for _, addr := range s.metadata.Network.IP {
		if addr.Family == "ipv4" && addr.Host == "true" && addr.Gateway == "true" {
			gw = net.ParseIP(addr.Address)
		}
		if addr.Family == "ipv4" && addr.Host == "false" {
			ip, ipnet, err = net.ParseCIDR(addr.Address + "/" + addr.Prefix)
			if err != nil {
				return nil, err
			}
		}
	}
	if ipnet == nil || ipnet.Mask == nil {
		return nil, fmt.Errorf("failed to get ipnet")
	}

	if dhcpreq == nil || dhcpreq.Options == nil {
		return nil, nil
	}

	opt := dhcpreq.Options[0]
	switch opt.Type {
	case dhcpv4.DHCP_OPT_MESSAGE_TYPE:
		switch dhcpv4.Operation(opt.Data[0]) {
		case dhcpv4.Operation(dhcpv4.DHCP_MSG_DISCOVER):
			dhcpres, err = dhcpv4.NewDHCPOffer(dhcpreq.Xid)
			if err != nil {
				return nil, err
			}
			copy(dhcpres.ClientHWAddr, mac[:dhcpres.HardwareLen])
			copy(dhcpres.YourIP, ip.To4())
			copy(dhcpres.ServerIP, gw.To4())
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(1, []byte(net.IP(ipnet.Mask).To4())))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(3, []byte(gw.To4())))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(5, []byte(net.ParseIP("8.8.8.8").To4())))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(6, []byte(net.ParseIP("8.8.8.8").To4())))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(28, []byte(net.ParseIP("85.143.223.255").To4())))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(15, []byte("simplecloud.club")))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(12, []byte(s.name)))
			var b [8]byte
			var bs []byte
			bs = b[:4]
			binary.BigEndian.PutUint32(bs, uint32(leaseTime))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(51, bs))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(54, []byte(gw.To4())))
			binary.BigEndian.PutUint32(bs, uint32(leaseTime/100*50))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(dhcpv4.DHCP_OPT_T1, bs))
			binary.BigEndian.PutUint32(bs, uint32(leaseTime/100*88))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(dhcpv4.DHCP_OPT_T2, bs))
			bs = b[:2]
			binary.BigEndian.PutUint16(bs, uint16(1500))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(dhcpv4.DHCP_OPT_INTERFACE_MTU, bs))
		case dhcpv4.Operation(dhcpv4.DHCP_MSG_REQUEST):
			dhcpres, err = dhcpv4.NewDHCPAck(dhcpreq.Xid)
			if err != nil {
				return nil, err
			}
			copy(dhcpres.ClientHWAddr, mac[:dhcpres.HardwareLen])
			copy(dhcpres.YourIP, ip.To4())
			copy(dhcpres.ServerIP, gw.To4())
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(1, []byte(net.IP(ipnet.Mask).To4())))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(3, []byte(gw.To4())))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(5, []byte(net.ParseIP("8.8.8.8").To4())))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(6, []byte(net.ParseIP("8.8.8.8").To4())))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(28, []byte(net.ParseIP("85.143.223.255").To4())))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(15, []byte("simplecloud.club")))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(12, []byte(s.name)))
			var b [8]byte
			var bs []byte
			bs = b[:4]
			binary.BigEndian.PutUint32(bs, uint32(leaseTime))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(51, bs))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(54, []byte(gw.To4())))
			binary.BigEndian.PutUint32(bs, uint32(leaseTime/100*50))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(dhcpv4.DHCP_OPT_T1, bs))
			binary.BigEndian.PutUint32(bs, uint32(leaseTime/100*88))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(dhcpv4.DHCP_OPT_T2, bs))
			bs = b[:2]
			binary.BigEndian.PutUint16(bs, uint16(1500))
			dhcpres.Options = append(dhcpres.Options, dhcpv4.NewOption(dhcpv4.DHCP_OPT_INTERFACE_MTU, bs))
		case dhcpv4.Operation(dhcpv4.DHCP_MSG_OFFER), dhcpv4.Operation(dhcpv4.DHCP_MSG_ACK):
			return nil, nil
		default:
			return nil, fmt.Errorf("unk dhcp msg: %d\n", dhcpv4.Operation(opt.Data[0]))
		}
	}
	var buf []byte
	if buf, err = dhcpres.Marshal(); err != nil {
		glog.Warningf(err.Error())
		return nil, err
	}

	udpres.Data = make([]byte, len(buf))
	copy(udpres.Data, buf)
	udpres.Length = udpres.Len()

	glog.Infof("%s dhcpv4 res: %+v\n", s.name, dhcpres)

	return udpres, nil
}
