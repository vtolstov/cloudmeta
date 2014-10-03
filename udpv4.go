package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"code.google.com/p/go.net/ipv4"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"github.com/golang/glog"
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
				glog.Warningf(err.Error())
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
				if dhcp4req.Operation == layers.DHCP_MSG_REQ {
					fmt.Printf("DHCP4: %+v\n", dhcp4req)

					dhcp4res, err := s.ServeUDPv4(&dhcp4req)
					if err != nil {
						glog.Warningf(err.Error())
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
						glog.Warningf(err.Error())
						continue
					}
				}
			}
		}
	}
}

func (s *Server) ServeUDPv4(dhcpreq *layers.DHCPv4) (*layers.DHCPv4, error) {
	dhcpres := &layers.DHCPv4{}

	glog.Infof("%s dhcpv4 req: %+v\n", s.name, dhcpreq)

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

	opt := dhcpreq.Options[0]
	switch opt.Type {
	case layers.DHCP_OPT_MESSAGE_TYPE:
		switch layers.Operation(opt.Data[0]) {
		case layers.Operation(layers.DHCP_MSG_DISCOVER):
			dhcpres, err = layers.NewDHCPOffer(dhcpreq.Xid)
			if err != nil {
				return nil, err
			}
			copy(dhcpres.ClientHWAddr, mac[:dhcpres.HardwareLen])
			copy(dhcpres.YourIP, ip.To4())
			copy(dhcpres.ServerIP, gw.To4())
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(1, []byte(net.IP(ipnet.Mask).To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(3, []byte(gw.To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(5, []byte(net.ParseIP("8.8.8.8").To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(6, []byte(net.ParseIP("8.8.8.8").To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(28, []byte(net.ParseIP("85.143.223.255").To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(15, []byte("simplecloud.club")))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(12, []byte(s.name+".simplecloud.club")))
			var b [8]byte
			var bs []byte
			bs = b[:4]
			binary.BigEndian.PutUint32(bs, uint32(leaseTime))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(51, bs))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(54, []byte(gw.To4())))
			binary.BigEndian.PutUint32(bs, uint32(leaseTime/100*50))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(layers.DHCP_OPT_T1, bs))
			binary.BigEndian.PutUint32(bs, uint32(leaseTime/100*88))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(layers.DHCP_OPT_T2, bs))
			bs = b[:2]
			binary.BigEndian.PutUint16(bs, uint16(1500))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(layers.DHCP_OPT_INTERFACE_MTU, bs))
		case layers.Operation(layers.DHCP_MSG_REQUEST):
			dhcpres, err = layers.NewDHCPAck(dhcpreq.Xid)
			if err != nil {
				return nil, err
			}
			copy(dhcpres.ClientHWAddr, mac[:dhcpres.HardwareLen])
			copy(dhcpres.YourIP, ip.To4())
			copy(dhcpres.ServerIP, gw.To4())
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(1, []byte(net.IP(ipnet.Mask).To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(3, []byte(gw.To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(5, []byte(net.ParseIP("8.8.8.8").To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(6, []byte(net.ParseIP("8.8.8.8").To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(28, []byte(net.ParseIP("85.143.223.255").To4())))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(15, []byte("simplecloud.club")))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(12, []byte(s.name+".simplecloud.club")))
			var b [8]byte
			var bs []byte
			bs = b[:4]
			binary.BigEndian.PutUint32(bs, uint32(leaseTime))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(51, bs))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(54, []byte(gw.To4())))
			binary.BigEndian.PutUint32(bs, uint32(leaseTime/100*50))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(layers.DHCP_OPT_T1, bs))
			binary.BigEndian.PutUint32(bs, uint32(leaseTime/100*88))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(layers.DHCP_OPT_T2, bs))
			bs = b[:2]
			binary.BigEndian.PutUint16(bs, uint16(1500))
			dhcpres.Options = append(dhcpres.Options, layers.NewOption(layers.DHCP_OPT_INTERFACE_MTU, bs))
		case layers.Operation(layers.DHCP_MSG_OFFER), layers.Operation(layers.DHCP_MSG_ACK):
			return nil, nil
		default:
			return nil, fmt.Errorf("unk dhcp msg: %d\n", layers.Operation(opt.Data[0]))
		}
	}

	return dhcpres, nil
}
