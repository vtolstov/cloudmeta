package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/vtolstov/svirtnet/internal/github.com/vtolstov/gopacket"
	"github.com/vtolstov/svirtnet/internal/github.com/vtolstov/gopacket/layers"
	"github.com/vtolstov/svirtnet/internal/golang.org/x/net/ipv4"
)

func cidr2bcast(cidr string) string {
	var a uint32
	var m uint32
	var s string
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return s
	}
	a |= uint32(ip.To4()[0])
	a |= uint32(ip.To4()[1]) << 8
	a |= uint32(ip.To4()[2]) << 16
	a |= uint32(ip.To4()[3]) << 24
	m |= uint32(net.IP(ipnet.Mask).To4()[0])
	m |= uint32(net.IP(ipnet.Mask).To4()[1]) << 8
	m |= uint32(net.IP(ipnet.Mask).To4()[2]) << 16
	m |= uint32(net.IP(ipnet.Mask).To4()[3]) << 24
	b := a | ^m
	s = fmt.Sprintf("%d.%d.%d.%d", byte(b), byte(b>>8), byte(b>>16), byte(b>>24))
	return s
}

func (s *Server) ListenAndServeUDPv4() {
	ipAddr := &net.IPAddr{IP: net.IPv4zero}
	conn, err := net.ListenIP("ip4:udp", ipAddr)
	if err != nil {
		l.Info(err.Error())
		return
	}
	defer conn.Close()
	if err = bindToDevice(conn, "tap"+s.name); err != nil {
		l.Info(err.Error())
		return
	}

	s.ipv4conn, err = ipv4.NewRawConn(conn)
	if err != nil {
		l.Info(err.Error())
		return
	}

	if err = s.ipv4conn.SetControlMessage(ipv4.FlagDst, true); err != nil {
		l.Warning(err.Error())
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
		l.Info(fmt.Sprintf("failed to get iface: %s", err.Error()))
		return
	}

	_ = gw
	_ = iface
	for {
		//		s.RLock()
		if s.shutdown {
			//		s.RUnlock()
			return
		}
		//s.RUnlock()

		s.ipv4conn.SetReadDeadline(time.Now().Add(time.Second))

		hdr, _, _, err := s.ipv4conn.ReadFrom(buffer)

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
				l.Warning(err.Error())
				return
			}
		}
		var ip4 layers.IPv4
		var udp layers.UDP
		var dhcp4req layers.DHCPv4
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &udp, &dhcp4req)
		decoded := []gopacket.LayerType{}
		err = parser.DecodeLayers(buffer, &decoded)
		for _, layerType := range decoded {
			switch layerType {
			/*
				case layers.LayerTypeIPv4:
					fmt.Printf("IP4: %+v\n", ip4)
				case layers.LayerTypeUDP:
					fmt.Printf("UDP: %+v\n", udp)
			*/
			case layers.LayerTypeDHCPv4:
				//			fmt.Printf("DHCP4: %+v\n", dhcp4req)
				if dhcp4req.Operation == layers.DHCP_MSG_REQ {

					dhcp4res, err := s.ServeUDPv4(&dhcp4req)
					if err != nil {
						l.Warning(err.Error())
						continue
					}

					buf := gopacket.NewSerializeBuffer()
					opts := gopacket.SerializeOptions{true, true}
					gopacket.SerializeLayers(buf, opts,
						/*					&layers.IPv4{Version: 4, TTL: 255, SrcIP: gw.To4(), DstIP: net.IPv4bcast.To4()}, */
						&layers.UDP{SrcPort: 67, DstPort: 68},
						dhcp4res)

					wcm := ipv4.ControlMessage{TTL: 255}
					wcm.Dst = net.IPv4bcast.To4()
					wcm.Src = gw.To4()
					wcm.IfIndex = iface.Index
					err = s.ipv4conn.WriteTo(&ipv4.Header{Len: 20, TOS: hdr.TOS, TotalLen: 20 + int(len(buf.Bytes())), FragOff: 0, TTL: 255, Protocol: int(layers.IPProtocolUDP), Src: gw.To4(), Dst: net.IPv4bcast.To4()}, buf.Bytes(), &wcm)
					if err != nil {
						l.Warning(err.Error())
						continue
					}
				}
			}
		}
	}
}

func (s *Server) ServeUDPv4(dhcpreq *layers.DHCPv4) (*layers.DHCPv4, error) {
	dhcpres := &layers.DHCPv4{}

	l.Info(fmt.Sprintf("%s dhcpv4 req: %+v\n", s.name, dhcpreq))

	leaseTime := 6000
	var ip net.IP
	var gw net.IP
	var mac net.HardwareAddr
	var ipnet *net.IPNet
	var err error
	var cidr string
	mac = dhcpreq.ClientHWAddr

	if s.metadata == nil {
		return nil, fmt.Errorf("err: metadata is nil")
	}

	for _, addr := range s.metadata.Network.IP {
		if addr.Family == "ipv4" && addr.Host == "false" {
			cidr = addr.Address + "/" + addr.Prefix
			ip, ipnet, err = net.ParseCIDR(cidr)
			if err != nil {
				return nil, err
			}
		}
		if addr.Family == "ipv4" && addr.Host == "true" && addr.Gateway == "true" && ipnet != nil && ipnet.Contains(net.ParseIP(addr.Address)) {
			gw = net.ParseIP(addr.Address)
			break
		}

	}
	if ipnet == nil || ipnet.Mask == nil || gw == nil || ip == nil {
		return nil, fmt.Errorf("failed to get ipv4 info")
	}

	opt := dhcpreq.Options[0]
	switch opt.Type {
	case layers.DHCP_OPT_MESSAGE_TYPE:
		switch layers.DHCPOperation(opt.Data[0]) {
		case layers.DHCPOperation(layers.DHCP_MSG_DISCOVER):
			dhcpres, err = layers.NewDHCPOffer(dhcpreq.Xid)
			if err != nil {
				return nil, err
			}
			copy(dhcpres.ClientHWAddr, mac[:dhcpres.HardwareLen])
			copy(dhcpres.YourIP, ip.To4())
			copy(dhcpres.ServerIP, gw.To4())
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(1, []byte(net.IP(ipnet.Mask).To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(3, []byte(gw.To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(5, []byte(net.ParseIP(s.metadata.Network.NameServer[0]).To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(6, []byte(net.ParseIP(s.metadata.Network.NameServer[0]).To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(28, []byte(net.ParseIP(cidr2bcast(cidr)).To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(15, []byte(s.metadata.Network.DomainName)))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(12, []byte(s.name)))
			var b [8]byte
			var bs []byte
			bs = b[:4]
			binary.BigEndian.PutUint32(bs, uint32(leaseTime))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(51, bs))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(54, []byte(gw.To4())))
			binary.BigEndian.PutUint32(bs, uint32(leaseTime/100*50))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(layers.DHCP_OPT_T1, bs))
			binary.BigEndian.PutUint32(bs, uint32(leaseTime/100*88))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(layers.DHCP_OPT_T2, bs))
			bs = b[:2]
			binary.BigEndian.PutUint16(bs, uint16(1500))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(layers.DHCP_OPT_INTERFACE_MTU, bs))
		case layers.DHCPOperation(layers.DHCP_MSG_REQUEST):
			dhcpres, err = layers.NewDHCPAck(dhcpreq.Xid)
			if err != nil {
				return nil, err
			}
			copy(dhcpres.ClientHWAddr, mac[:dhcpres.HardwareLen])
			copy(dhcpres.YourIP, ip.To4())
			copy(dhcpres.ServerIP, gw.To4())
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(1, []byte(net.IP(ipnet.Mask).To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(3, []byte(gw.To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(5, []byte(net.ParseIP(s.metadata.Network.NameServer[0]).To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(6, []byte(net.ParseIP(s.metadata.Network.NameServer[0]).To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(28, []byte(net.ParseIP(cidr2bcast(cidr)).To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(15, []byte(s.metadata.Network.DomainName)))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(12, []byte(s.name)))
			var b [8]byte
			var bs []byte
			bs = b[:4]
			binary.BigEndian.PutUint32(bs, uint32(leaseTime))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(51, bs))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(54, []byte(gw.To4())))
			binary.BigEndian.PutUint32(bs, uint32(leaseTime/100*50))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(layers.DHCP_OPT_T1, bs))
			binary.BigEndian.PutUint32(bs, uint32(leaseTime/100*88))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(layers.DHCP_OPT_T2, bs))
			bs = b[:2]
			binary.BigEndian.PutUint16(bs, uint16(1500))
			dhcpres.Options = append(dhcpres.Options, layers.NewDHCPOption(layers.DHCP_OPT_INTERFACE_MTU, bs))
		case layers.DHCPOperation(layers.DHCP_MSG_OFFER), layers.DHCPOperation(layers.DHCP_MSG_ACK):
			return nil, nil
		default:
			return nil, fmt.Errorf("unk dhcp msg: %d\n", layers.DHCPOperation(opt.Data[0]))
		}
	}

	return dhcpres, nil
}
