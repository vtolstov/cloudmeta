package main

import (
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"time"

	"crypto/tls"

	"code.google.com/p/go.net/ipv4"
	"code.google.com/p/go.net/ipv6"
	"github.com/alexzorin/libvirt-go"

	"./dhcpv4"
	"./icmpv6"
)

type IP struct {
	Family  string `xml:"family,attr"`
	Address string `xml:"address,attr"`
	Prefix  string `xml:"prefix,attr,omitempty"`
	Peer    string `xml:"peer,attr,omitempty"`
	Host    string `xml:"host,attr,omitempty"`
	Gateway string `xml:"gateway,attr,omitempty"`
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

var httpTransport *http.Transport = &http.Transport{
	Dial:            (&net.Dialer{DualStack: true}).Dial,
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
var httpClient *http.Client = &http.Client{Transport: httpTransport, Timeout: 10 * time.Second}

func cleanExists(name string, ips []IP) []IP {
	ret := make([]IP, len(ips))
	copy(ret[:], ips[:])

	iface, err := net.InterfaceByName("tap" + name)
	if err != nil {
		return ips
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ips
	}
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
		if addr.Family == "ipv4" && addr.Host == "true" {
			// TODO: use netlink
			if addr.Peer != "" {
				cmd = exec.Command("ip", "-4", "a", "add", peer, "peer", addr.Address+"/"+addr.Prefix, "dev", "tap"+s.name)
			} else {
				cmd = exec.Command("ip", "-4", "a", "add", addr.Address+"/"+addr.Prefix, "dev", "tap"+s.name)
			}
			err = cmd.Run()
			if err != nil {
				return fmt.Errorf("Failed to add ip for: %s", addr.Address+"/"+addr.Prefix)
			}
		}
	}

	cmd = exec.Command("sysctl", "-w", "net.ipv4.conf.tap"+s.name+".proxy_arp=1")
	aa, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to enable proxy_arp: %s sysctl -w net.ipv4.conf.tap%s.proxy_arp=1", aa, s.name)
	}

	log.Printf("%s ListenAndServeIPv4\n", s.name)
	go s.ListenAndServeIPv4()

	for _, addr := range metaIP {
		if addr.Family == "ipv6" && addr.Host == "true" {
			// TODO: use netlink
			cmd := exec.Command("ip", "-6", "a", "add", addr.Address+"/"+addr.Prefix, "dev", "tap"+s.name)
			err = cmd.Run()
			if err != nil {
				return fmt.Errorf("Failed to add ip for: %s", addr.Address+"/"+addr.Prefix)
			}

			cmd = exec.Command("ip", "-6", "r", "replace", addr.Address+"/"+addr.Prefix, "dev", "tap"+s.name, "proto", "static", "table", "200")
			err = cmd.Run()
			if err != nil {
				return fmt.Errorf("Failed to replace route for: %s", addr.Address+"/"+addr.Prefix)
			}
		}
	}

	log.Printf("%s ListenAndServeIPv6\n", s.name)
	go s.ListenAndServeIPv6()

	log.Printf("%s ListenAndServerHTTP\n", s.name)
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

	if s.httpconn != nil {
		err = s.httpconn.Close()
		if err != nil {
			return err
		}
	}

	if s.metadata == nil {
		return nil
	}

	for _, addr := range s.metadata.Network.IP {
		if addr.Family == "ipv6" && addr.Host == "true" {
			/*
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
			*/
			// TODO: use netlink
			cmd := exec.Command("ip", "-6", "r", "del", addr.Address+"/"+addr.Prefix, "dev", "tap"+s.name, "proto", "static", "table", "200")
			err = cmd.Run()
			if err != nil {
				return err
			}
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
	conn, err := net.ListenTCP("tcp4", ipAddr)
	if err != nil {
		return err
	}
	err = bindToDevice2(conn, "tap"+s.name)
	if err != nil {
		return err
	}

	s.httpconn = conn

	//	http.Handle("/", s)

	httpsrv := &http.Server{
		//		Addr:           "169.254.169.254:80",
		Handler:        s,
		ReadTimeout:    20 * time.Second,
		WriteTimeout:   20 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Printf("%s http %s", s.name, httpsrv.Serve(s.httpconn))
	return nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s http req: Host:%s RemoteAddr:%s URL:%s\n", s.name, r.Host, r.RemoteAddr, r.URL)

	var res *http.Response
	var host string
	var port string

	u, _ := url.Parse(s.metadata.CloudConfig.URL)
	if strings.Index(u.Host, ":") > 0 {
		host, port, _ = net.SplitHostPort(u.Host)
	} else {
		host = u.Host
	}
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	addrs, err := net.LookupIP(host)
	if err != nil {
		w.WriteHeader(503)
		return
	}

	var addr net.IP

	for _, addr = range addrs {
		if addr.To4() == nil {
			break
		}
	}

	switch r.URL.String() {
	case "/":
		w.Write([]byte("2009-04-04\nlatest\n"))
	case "/2009-04-04/meta-data/", "/latest/meta-data/":
		w.Write([]byte("public-hostname\nhostname\nlocal-hostname\ninstance-id\npublic-ipv4\npublic-keys\n"))
	case "/2009-04-04/meta-data/public-hostname", "/2009-04-04/meta-data/hostname", "/2009-04-04/meta-data/local-hostname", "/latest/meta-data/public-hostname", "/latest/meta-data/hostname", "/latest/meta-data/local-hostname":
		w.Write([]byte(s.name + ".simplecloud.club\n"))
	case "/2009-04-04/meta-data/instance-id", "/latest/meta-data/instance-id":
		w.Write([]byte(s.name + "\n"))
	case "/2009-04-04/meta-data/public-ipv4", "/latest/meta-data/public-ipv4":
		w.Write([]byte(""))
	case "/2009-04-04/meta-data/public-keys", "/latest/meta-data/public-keys":
		w.Write([]byte("0\n"))
	case "/2009-04-04/meta-data/public-keys/0/openssh-key", "/latest/meta-data/public-keys/0/openssh-key":
		w.Write([]byte(""))
	case "/2009-04-04/user-data", "/latest/user-data":
		req, _ := http.NewRequest("GET", s.metadata.CloudConfig.URL, nil)
		req.URL = u
		req.URL.Host = net.JoinHostPort(addr.String(), port)
		req.Host = host
		res, err = httpClient.Do(req)
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

		n, _, _, err := s.ipv4conn.ReadFrom(buffer)

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

		req := &dhcpv4.DHCP{}
		req.Write(buffer[:n])
		log.Printf("ipv4 req: %+v\n", req)
		//if req.SIAddr().Equal(net.IPv4(0, 0, 0, 0)) || req.SIAddr().Equal(net.IP{}) {
		res, err := s.ServeDHCP(req)
		if err != nil {
			log.Printf("Error Serving DHCP: %s\n" + err.Error())
			return err
		}
		if res == nil {
			log.Printf("%s dhcpv4 nothing served\n", s.name)
			continue
		}
		log.Printf("ipv4 res: %+v\n", res)
		buf := make([]byte, res.Len())
		if _, err := res.Read(buf); err != nil {
			return err
		}

		var gw net.IP
		for _, addr := range s.metadata.Network.IP {
			if addr.Family == "ipv4" && addr.Host == "false" {
				if addr.Gateway == "true" {
					gw = net.ParseIP(addr.Address)
				}
			}
		}
		iface, err := net.InterfaceByName("tap" + s.name)
		if err != nil {
			return err
		}
		wcm := ipv4.ControlMessage{TTL: 255}
		wcm.Dst = net.IPv4bcast
		wcm.Src = gw
		wcm.IfIndex = iface.Index

		_, err = s.ipv4conn.WriteTo(buf, &wcm, &net.UDPAddr{IP: wcm.Dst, Port: 68})
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
			log.Printf("%s ipv6 req: %+v\n", s.name, rs)
			for _, addr := range s.metadata.Network.IP {
				// TODO fix ipv6 addr
				if addr.Family == "ipv6" && addr.Host == "true" {
					res := icmpv6.NewRouterAdvertisement(srcIP, net.IPv6linklocalallnodes, iface.HardwareAddr, addr.Address, addr.Prefix)
					log.Printf("%s ipv6 res: %+v\n", s.name, res)
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
	}

	return nil
}

func (s *Server) ServeDHCP(req *dhcpv4.DHCP) (*dhcpv4.DHCP, error) {
	leaseTime := 6000
	var ip net.IP
	var gw net.IP
	var mac net.HardwareAddr
	var ipnet *net.IPNet
	var err error
	mac = req.ClientHWAddr

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

	if req == nil || req.Options == nil {
		return nil, nil
	}

	opt := req.Options[0]
	switch opt.OptionType() {
	case dhcpv4.DHCP_OPT_MESSAGE_TYPE:
		switch dhcpv4.DHCPOperation(opt.Bytes()[0]) {
		case dhcpv4.DHCPOperation(dhcpv4.DHCP_MSG_DISCOVER):
			log.Printf("offer\n")
			res, err := dhcpv4.NewDHCPOffer(req.Xid, mac)
			if err != nil {
				return nil, err
			}
			copy(res.YourIP, ip.To4())
			copy(res.ServerIP, gw.To4())
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(1, []byte(net.IP(ipnet.Mask).To4())))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(3, []byte(gw.To4())))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(5, []byte(net.ParseIP("8.8.8.8").To4())))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(6, []byte(net.ParseIP("8.8.8.8").To4())))
			req.Options = append(req.Options, dhcpv4.DHCPNewOption(28, []byte(net.ParseIP("85.143.223.255").To4())))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(15, []byte("simplecloud.club")))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(12, []byte(s.name)))
			var b [8]byte
			var bs []byte
			bs = b[:4]
			binary.BigEndian.PutUint32(bs, uint32(leaseTime))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(51, bs))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(54, []byte(gw.To4())))
			binary.BigEndian.PutUint32(bs, uint32(leaseTime/100*50))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(dhcpv4.DHCP_OPT_T1, bs))
			binary.BigEndian.PutUint32(bs, uint32(leaseTime/100*88))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(dhcpv4.DHCP_OPT_T2, bs))
			bs = b[:2]
			binary.BigEndian.PutUint16(bs, uint16(1500))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(dhcpv4.DHCP_OPT_INTERFACE_MTU, bs))
			return res, nil
		case dhcpv4.DHCPOperation(dhcpv4.DHCP_MSG_REQUEST):
			log.Printf("ack\n")
			res, err := dhcpv4.NewDHCPAck(req.Xid, mac)
			if err != nil {
				return nil, err
			}
			copy(res.YourIP, ip.To4())
			copy(res.ServerIP, gw.To4())
			var b [8]byte
			var bs []byte
			bs = b[:4]
			binary.BigEndian.PutUint32(bs, uint32(leaseTime))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(51, bs))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(1, []byte(net.IP(ipnet.Mask).To4())))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(3, []byte(gw.To4())))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(6, []byte(net.ParseIP("8.8.8.8").To4())))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(5, []byte(net.ParseIP("8.8.8.8").To4())))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(28, []byte(net.ParseIP("85.143.223.255").To4())))
			binary.BigEndian.PutUint32(bs, uint32(leaseTime/100*50))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(dhcpv4.DHCP_OPT_T1, bs))
			binary.BigEndian.PutUint32(bs, uint32(leaseTime/100*88))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(dhcpv4.DHCP_OPT_T2, bs))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(15, []byte("simplecloud.club")))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(12, []byte(s.name)))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(54, []byte(gw.To4())))
			bs = b[:2]
			binary.BigEndian.PutUint16(bs, uint16(1500))
			res.Options = append(res.Options, dhcpv4.DHCPNewOption(dhcpv4.DHCP_OPT_INTERFACE_MTU, bs))
			return res, nil
		default:
			log.Printf("unk %d\n", dhcpv4.DHCPOperation(opt.Bytes()[0]))
		}

	}
	return nil, fmt.Errorf("strange dhcpv4 error")
}
