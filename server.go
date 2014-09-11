package main

import (
	"encoding/xml"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"time"

	"code.google.com/p/go.net/ipv4"
	"code.google.com/p/go.net/ipv6"
	"github.com/alexzorin/libvirt-go"

	"./dhcpv4"
	"./icmpv6"
	"./netlink"
)

type IP struct {
	Family  string `xml:"family,attr"`
	Address string `xml:"address,attr"`
	Prefix  string `xml:"prefix,attr,omitempty"`
	Peer    string `xml:"peer,attr,omitempty"`
}

type Storage struct {
	Size   string `xml:"size"`
	Target string `xml:"target"`
}

type CloudConfig struct {
	URL string `xml:"url,omitempty"`
}

type Network struct {
	IP []IP `xml:"ip"`
}

type Metadata struct {
	Network     Network     `xml:"network"`
	CloudConfig CloudConfig `xml:"cloud-config"`
}

type Server struct {
	// shutdown flag
	shutdown bool

	// domain name
	name string

	// domain metadata
	metadata *Metadata

	// DHCPv4 conn
	ipv4conn *ipv4.PacketConn

	// RA conn
	ipv6conn *ipv6.PacketConn

	// Libvirt conn
	libvirt libvirt.VirConnection

	// HTTP conn
	httpconn net.Listener
}

func cleanExists(name string, ips []IP) (ret []IP) {
	iface, err := net.InterfaceByName("tap" + name)
	if err != nil {
		return nil
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}

	copy(ret[:], ips[:])
	for _, addr := range addrs {
	loop:
		for i, ip := range ret {
			if ip.Address+"/"+ip.Prefix == addr.String() {
				copy(ret[i:], ret[i+1:])
				ret[len(ret)-1] = IP{}
				ret = ret[:len(ret)-1]
				break loop
			}
		}
	}
	return ret
}

var servers map[string]*Server

func init() {
	servers = make(map[string]*Server, 1024)
}

func (s *Server) Start() error {
	var buf string
	var err error
	var domain libvirt.VirDomain

	if s == nil || s.name == "" {
		return errors.New("invalid server config")
	}

	s.libvirt, err = libvirt.NewVirConnectionReadOnly("qemu:///system")
	if err != nil {
		return err
	}

	domain, err = s.libvirt.LookupDomainByName(s.name)
	if err != nil {
		return err
	}

	buf, err = domain.GetMetadata(libvirt.VIR_DOMAIN_METADATA_ELEMENT, "http://simplecloud.ru/", libvirt.VIR_DOMAIN_MEM_LIVE)
	if err != nil {
		return err
	}
	s.metadata = &Metadata{}
	if err = xml.Unmarshal([]byte(buf), s.metadata); err != nil {
		return err
	}

	iface, err := net.InterfaceByName("vlan1001")
	if err != nil {
		return err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}
	var peer string
	var cmd *exec.Cmd
	for _, addr := range addrs {
		a := strings.Split(addr.String(), "/")[0]
		ip := net.ParseIP(a)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			peer = ip.String()
		}
	}

	metaIP := cleanExists(s.name, s.metadata.Network.IP)

	for _, addr := range metaIP {
		if addr.Family != "ipv4" {
			continue
		}
		// TODO: use netlink
		if addr.Peer != "" {
			cmd = exec.Command("ip", "-4", "a", "add", peer, "peer", addr.Address+"/"+addr.Prefix, "dev", "tap"+s.name)
		} else {
			cmd = exec.Command("ip", "-4", "a", "add", addr.Address+"/"+addr.Prefix, "dev", "tap"+s.name)
		}
		err = cmd.Run()
		if err != nil {
			log.Printf("fff1 ip -4 a add %s peer %s dev %s\n", peer, addr.Address+"/"+addr.Prefix, "tap"+s.name)
			return err
		}
	}

	cmd = exec.Command("sysctl", "-w", "net.ipv4.conf.tap"+s.name+".proxy_arp", "=", "1")
	err = cmd.Run()
	if err != nil {
		log.Printf(" %s\n", err.Error())
	}

	log.Printf("ListenAndServeIPv4 %s\n", s.name)
	go s.ListenAndServeIPv4()

	for _, addr := range metaIP {
		if addr.Family != "ipv6" {
			continue
		}
		// TODO: use netlink
		cmd := exec.Command("ip", "-6", "a", "add", addr.Address+"/"+addr.Prefix, "dev", "tap"+s.name)
		err = cmd.Run()
		if err != nil {
			log.Printf("fff1 ip -6 a add %s dev %s\n", addr.Address+"/"+addr.Prefix, "tap"+s.name)
			return err
		}

		cmd = exec.Command("ip", "-6", "r", "replace", addr.Address+"/"+addr.Prefix, "dev", "tap"+s.name, "proto", "static", "table", "200")
		err = cmd.Run()
		if err != nil {
			log.Printf("fff5 %s\n", err.Error())
			return err
		}
	}

	log.Printf("ListenAndServeIPv6 %s\n", s.name)
	go s.ListenAndServeIPv6()

	log.Printf("ListenAdnServerHTTP %s\n", s.name)
	go s.ListenAndServerHTTP()

	select {}
	return nil
}

func (s *Server) Stop() (err error) {
	s.shutdown = true
	if ok, err := s.libvirt.IsAlive(); ok && err == nil {
		err = s.libvirt.UnrefAndCloseConnection()
		if err != nil {
			return err
		}
	}

	if s.ipv4conn != nil {
		err = s.ipv4conn.Close()
		if err != nil {
			return err
		}
	}
	if s.ipv6conn != nil {
		err = s.ipv6conn.Close()
		if err != nil {
			return err
		}
	}

	if s.metadata == nil {
		return nil
	}

	for _, addr := range s.metadata.Network.IP {
		if addr.Family != "ipv6" {
			continue
		}
		iface, err := net.InterfaceByName("tap" + s.name)
		if err != nil {
			return err
		}
		ip, net, err := net.ParseCIDR(addr.Address + "1/" + addr.Prefix)
		if err != nil {
			return err
		}
		err = netlink.NetworkLinkAddIp(iface, ip, net)
		if err != nil {
			return err
		}
		// TODO: use netlink
		cmd := exec.Command("ip", "-6", "r", "del", addr.Address+"/"+addr.Prefix, "dev", "tap"+s.name, "proto", "static", "table", "200")
		err = cmd.Run()
		if err != nil {
			return err
		}
	}

	return nil
}

func bindToDevice(conn net.PacketConn, device string) error {
	ptrVal := reflect.ValueOf(conn)
	val := reflect.Indirect(ptrVal)
	//next line will get you the net.netFD
	fdmember := val.FieldByName("fd")
	val1 := reflect.Indirect(fdmember)
	netFdPtr := val1.FieldByName("sysfd")
	fd := int(netFdPtr.Int())
	//fd now has the actual fd for the socket
	return syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
}

func bindToDevice2(conn *net.TCPListener, device string) error {
	ptrVal := reflect.ValueOf(conn)
	val := reflect.Indirect(ptrVal)
	//next line will get you the net.netFD
	fdmember := val.FieldByName("fd")
	val1 := reflect.Indirect(fdmember)
	netFdPtr := val1.FieldByName("sysfd")
	fd := int(netFdPtr.Int())
	//fd now has the actual fd for the socket
	return syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, device)
}

func (s *Server) ListenAndServerHTTP() (err error) {
	ipAddr := &net.TCPAddr{IP: net.ParseIP("169.254.169.254"), Port: 80}
	conn, err := net.ListenTCP("tcp", ipAddr)
	if err != nil {
		log.Printf("fff6 %s\n", err.Error())
		return err
	}
	err = bindToDevice2(conn, "tap"+s.name)
	if err != nil {
		return err
	}

	s.httpconn = conn

	http.Handle("/", s)

	httpsrv := &http.Server{
		Addr:           "169.254.169.254:80",
		Handler:        nil,
		ReadTimeout:    20 * time.Second,
		WriteTimeout:   20 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	httpsrv.Serve(s.httpconn)
	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.String() {
	case "/":
		w.Write([]byte(""))
	case "/2009-04-04/meta-data/instance-id":
		w.Write([]byte(s.name))
	case "/2009-04-04/user-data":
		res, err := http.Get(s.metadata.CloudConfig.URL)
		if res != nil && res.Body != nil {
			defer res.Body.Close()
		}
		if res == nil && err != nil {
			log.Printf("%s\n", err.Error())
			w.WriteHeader(503)
			return
		}
		io.Copy(w, res.Body)
		return
	default:
		log.Printf("http: %+v\n", r)
		w.WriteHeader(503)
	}
	return
}

func (s *Server) ListenAndServeIPv4() (err error) {
	ipAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 67}
	conn, err := net.ListenUDP("udp4", ipAddr)
	if err != nil {
		return err
	}
	err = bindToDevice(conn, "tap"+s.name)
	if err != nil {
		return err
	}

	s.ipv4conn = ipv4.NewPacketConn(conn)

	buffer := make([]byte, 1024)

	for {
		if s.shutdown {
			return nil
		}

		s.ipv4conn.SetReadDeadline(time.Now().Add(time.Second))

		n, msg, src, err := s.ipv4conn.ReadFrom(buffer)

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
				return err
			}
		}

		_ = n
		_ = msg
		_ = src
		req := dhcpv4.DHCP{}
		req.Write(buffer[:n])
		log.Printf("ipv4 req: %+v\n", req)
		//if req.SIAddr().Equal(net.IPv4(0, 0, 0, 0)) || req.SIAddr().Equal(net.IP{}) {
		res, err := s.ServeDHCP(req)
		if err != nil {
			log.Printf("Error Serving DHCP: %s\n" + err.Error())
			return err
		}

		log.Printf("ipv4: %+v\n", res)
		var buf []byte
		res.Read(buf)
		_, err = s.ipv4conn.WriteTo(buf, msg, &net.UDPAddr{IP: net.IPv4bcast, Port: 68})
		if err != nil {
			log.Printf("Error Writing: %s\n" + err.Error())
			return err
		}
		//		}

	}
	return nil
}

func (s *Server) ListenAndServeIPv6() (err error) {
	ipAddr := &net.IPAddr{IP: net.IPv6linklocalallrouters, Zone: "tap" + s.name}
	conn, err := net.ListenIP("ip6:58", ipAddr)
	if err != nil {
		return err
	}
	if err = bindToDevice(conn, "tap"+s.name); err != nil {
		return err
	}
	s.ipv6conn = ipv6.NewPacketConn(conn)

	if err = s.ipv6conn.SetControlMessage(ipv6.FlagDst, true); err != nil {
		return err
	}

	buffer := make([]byte, 1024)

	for {
		if s.shutdown {
			return nil
		}

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
			log.Printf("can't find iface %s: %s\n", device, err.Error())
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			log.Printf("can't get addresses from %s: %s\n", iface.Name, err.Error())
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
		err = req.UnmarshalBinary(buffer)
		if err != nil {
			log.Printf(err.Error())
			continue
		}
		switch req.ICMPType() {
		case ipv6.ICMPTypeRouterSolicitation:
			rs := &icmpv6.RouterSolicitation{}
			rs.UnmarshalBinary(req.Data)
			log.Printf("ipv6 req: %+v\n", rs)
			for _, addr := range s.metadata.Network.IP {
				if addr.Family != "ipv6" {
					continue
				}
				res := icmpv6.NewRouterAdvertisement(srcIP, net.IPv6linklocalallnodes, iface.HardwareAddr, addr.Address, addr.Prefix)
				log.Printf("ipv6 res: %+v\n", res)
				b, err := res.MarshalBinary()
				if err != nil {
					log.Printf(err.Error())
					continue
				}
				wcm := ipv6.ControlMessage{HopLimit: 255}
				wcm.Dst = net.IPv6linklocalallnodes
				wcm.IfIndex = iface.Index
				_, err = s.ipv6conn.WriteTo(b, &wcm, src)
				if err != nil {
					log.Printf(err.Error())
					continue
				}
			}
		}
	}

	return nil
}

func (s *Server) ServeDHCP(req dhcpv4.DHCP) (res dhcpv4.DHCP, err error) {
	return
}
