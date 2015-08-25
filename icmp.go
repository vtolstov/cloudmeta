package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"encoding/binary"
	"errors"
	"strconv"

	"github.com/vtolstov/svirtnet/internal/golang.org/x/net/ipv6"
)

func (s *Server) ListenAndServeICMPv6() {
	ipAddr := &net.IPAddr{IP: net.IPv6linklocalallrouters, Zone: "tap" + s.name}
	conn, err := net.ListenIP("ip6:58", ipAddr)
	if err != nil {
		l.Info("error: " + err.Error())
		return
	}
	defer conn.Close()
	if err = bindToDevice(conn, "tap"+s.name); err != nil {
		l.Info("error: " + err.Error())
		return
	}
	s.ipv6conn = ipv6.NewPacketConn(conn)

	if err = s.ipv6conn.SetControlMessage(ipv6.FlagDst, true); err != nil {
		l.Info(err.Error())
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
			//			l.Info(err.Error())
			continue
		}

		req := &ICMPv6{}
		err = req.Unmarshal(buffer)
		if err != nil {
			//		l.Info(err.Error())
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
				ticker.Stop()
				return
			}
			s.sendRA(nil)
		}
	}
}

func (s *Server) sendRA(src net.Addr) {
	var srcIP net.IP
	var ipAddr net.Addr

	iface, err := net.InterfaceByName("tap" + s.name)
	if err != nil {
		l.Info("can't find iface tap" + s.name + " " + err.Error())
		return
	}
	addrs, err := iface.Addrs()
	if err != nil {
		l.Info("can't get addresses from " + iface.Name + " " + err.Error())
		return
	}
	for _, addr := range addrs {
		ip, ipnet, err := net.ParseCIDR(addr.String())
		_ = ipnet
		if err != nil {
			l.Info(err.Error())
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
		l.Info(fmt.Sprintf("ipv6 add missing for tap %s %s", s.name, srcIP))
		return
	}
	res, err := s.ServeICMPv6(srcIP, &ICMPv6{Type: uint8(ipv6.ICMPTypeRouterSolicitation)})
	if err != nil {
		l.Info(err.Error())
		return
	}

	for _, msg := range res {
		buf := make([]byte, msg.Len())
		buf, err = msg.Marshal()
		if err != nil {
			l.Info(fmt.Sprintf("%s err %s", s.name, err.Error()))
			continue
		}

		wcm := ipv6.ControlMessage{HopLimit: 255}
		wcm.Dst = net.IPv6linklocalallnodes
		wcm.IfIndex = iface.Index
		if _, err = s.ipv6conn.WriteTo(buf, &wcm, ipAddr); err != nil {
			l.Info(fmt.Sprintf("%s err %s", s.name, err.Error()))
			continue
		}
	}
}

func (s *Server) ServeICMPv6(src net.IP, req *ICMPv6) ([]*ICMPv6, error) {
	var res []*ICMPv6
	switch req.ICMPType() {
	case ipv6.ICMPTypeRouterSolicitation:
		for _, addr := range s.metadata.Network.IP {
			// TODO fix ipv6 addr
			if addr.Family == "ipv6" && addr.Host == "true" {
				ra := NewRouterAdvertisement(src, net.IPv6linklocalallnodes, addr.Address, addr.Prefix)
				buf, err := ra.Marshal()
				if err != nil {
					return nil, err
				}
				res = append(res, &ICMPv6{Type: ra.Type, Code: ra.Code, Checksum: ra.Checksum, Data: buf[4:]})
			}
		}
	}
	return res, nil
}

func (i *ICMPv6) ICMPType() ipv6.ICMPType { return ipv6.ICMPType(i.Type) }

type ICMPv6 struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Data     []byte
}

func (i *ICMPv6) Len() (n uint16) {
	return uint16(4 + len(i.Data))
}

func (i *ICMPv6) Marshal() (data []byte, err error) {
	data = make([]byte, int(i.Len()))
	data[0] = i.Type
	data[1] = i.Code
	binary.BigEndian.PutUint16(data[2:4], i.Checksum)
	copy(data[4:], i.Data)
	return
}

func (i *ICMPv6) Unmarshal(data []byte) error {
	if len(data) < 4 {
		return errors.New("The []byte is too short to unmarshal a full ICMP message.")
	}
	i.Type = data[0]
	i.Code = data[1]
	i.Checksum = binary.BigEndian.Uint16(data[2:4])

	for n, _ := range data[4:] {
		i.Data = append(i.Data, data[n])
	}
	return nil
}

type SourceLinkLayer struct {
	Type   uint8
	Length uint8
	HWSrc  net.HardwareAddr
}

type MTU struct {
	Type   uint8
	Length uint8
	MTU    uint32
}

type PrefixInfo struct {
	Type           uint8
	Length         uint8
	PrefixLength   uint8
	OnLinkFlag     bool
	AutonomousFlag bool
	ValidLifeTime  uint32
	PrefLifeTime   uint32
	Prefix         net.IP
}

type RouterAdvertisement struct {
	Type        uint8
	Code        uint8
	Checksum    uint16
	HopLimit    uint8
	ManagedFlag bool
	OtherFlag   bool
	LifeTime    uint16
	ReachTime   uint32
	RetransTime uint32
	SLL         SourceLinkLayer
	MTU         MTU
	Prefix      PrefixInfo
}

type RouterSolicitation struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	SLL      SourceLinkLayer
}

func ipv6PseudoHeader(src, dst net.IP, nextHeader int) []byte {
	b := make([]byte, 2*net.IPv6len+8)
	copy(b[:net.IPv6len], src)
	copy(b[net.IPv6len:], dst)
	b[2*net.IPv6len+7] = byte(nextHeader)
	return b
}

func checksum(b []byte) uint16 {
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	s = ^s & 0xffff
	return uint16(s<<8 | s>>(16-8))
}

func NewRouterAdvertisement(src, dst net.IP, prefix string, prefixlen string) (ra *RouterAdvertisement) {
	ra = &RouterAdvertisement{}
	ra.Type = 134
	ra.Code = 0
	ra.LifeTime = 9000
	ra.HopLimit = 64
	ra.Checksum = checksum(ipv6PseudoHeader(src, dst, 58))
	preflen, _ := strconv.ParseUint(prefixlen, 10, 8)
	ra.Prefix = PrefixInfo{Type: 3, Length: 4, ValidLifeTime: 86400, PrefLifeTime: 14400, Prefix: net.ParseIP(prefix), PrefixLength: uint8(preflen), OnLinkFlag: true, AutonomousFlag: true}
	return ra
}

func (ra *RouterAdvertisement) Marshal() (data []byte, err error) {
	data = make([]byte, 16+32)
	n := 0
	data[n] = ra.Type
	n += 1
	data[n] = ra.Code
	n += 1
	binary.BigEndian.PutUint16(data[n:], ra.Checksum)
	n += 2
	data[n] = ra.HopLimit
	n += 1
	data[n] = 0 // Flags
	n += 1

	binary.BigEndian.PutUint16(data[n:], ra.LifeTime)
	n += 2
	binary.BigEndian.PutUint32(data[n:], ra.ReachTime)
	n += 4
	binary.BigEndian.PutUint32(data[n:], ra.RetransTime)
	n += 4

	data[n] = ra.Prefix.Type
	n += 1
	data[n] = ra.Prefix.Length
	n += 1
	data[n] = ra.Prefix.PrefixLength
	n += 1
	flags := uint8(0)
	if ra.Prefix.OnLinkFlag {
		setBit(&flags, 7)
	}
	if ra.Prefix.AutonomousFlag {
		setBit(&flags, 6)
	}

	data[n] = flags
	n += 1 // Prefix Flags
	binary.BigEndian.PutUint32(data[n:], ra.Prefix.ValidLifeTime)
	n += 4
	binary.BigEndian.PutUint32(data[n:], ra.Prefix.PrefLifeTime)
	n += 4
	n += 4 // Prefix Reserved
	copy(data[n:], ra.Prefix.Prefix)
	return
}

func setBit(num *uint8, position ...byte) {
	const MASK = 1

	for _, pos := range position {
		*num |= MASK << pos
	}
}

func (rs *RouterSolicitation) Unmarshal(data []byte) error {
	rs.Type = data[0]
	rs.Code = data[1]
	rs.Checksum = binary.BigEndian.Uint16(data[2:4])
	rs.SLL = SourceLinkLayer{}
	rs.SLL.Type = data[8]
	rs.SLL.Length = data[9]
	rs.SLL.HWSrc = net.HardwareAddr(make([]byte, 6))
	copy(rs.SLL.HWSrc, data[10:])
	return nil
}
