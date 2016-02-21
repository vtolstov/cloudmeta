package main

import (
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"

	"crypto/tls"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type IP struct {
	Family  string `xml:"family,attr"`
	Address string `xml:"address,attr"`
	Prefix  string `xml:"prefix,attr,omitempty"`
	Peer    string `xml:"peer,attr,omitempty"`
	Host    string `xml:"host,attr,omitempty"`
	Gateway string `xml:"gateway,attr,omitempty"`
}

type CloudConfig struct {
	URL string `xml:"url,omitempty"`
}

type Network struct {
	NameServer []string `xml:"nameserver,omitempty"`
	DomainName string   `xml:"domainname,omitempty"`
	IP         []*IP    `xml:"ip"`
}

type Agent struct {
	Log string `xml:"log,omitempty"`
}

type Metadata struct {
	Network     *Network     `xml:"network"`
	CloudConfig *CloudConfig `xml:"cloud-config"`
	Agent       *Agent       `xml:"agent,omitempty"`
}

type Server struct {
	// shutdown срфт
	done chan struct{}

	// domain name
	name string

	// domain metadata
	metadata Metadata

	// DHCPv4 conn
	ipv4conn *ipv4.RawConn

	// RA conn
	ipv6conn *ipv6.PacketConn

	// thread safe
	sync.Mutex

	downtime time.Time
}

var httpTransport *http.Transport = &http.Transport{
	Dial:            (&net.Dialer{DualStack: true}).Dial,
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
var httpClient *http.Client = &http.Client{Transport: httpTransport, Timeout: 10 * time.Second}

func cleanExists(name string, ips []*IP) []*IP {
	ret := make([]*IP, len(ips))
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
				ret[len(ret)-1] = &IP{}
				ret = ret[:len(ret)-1]
				break loop
			}
		}
	}
	return ret
}

type Servers struct {
	mp map[string]*Server
	sync.Mutex
}

func (srvs *Servers) Add(name string, srv *Server) {
	srvs.mp[name] = srv
}

func (srvs *Servers) Del(name string) {
	delete(srvs.mp, name)
}

func (srvs *Servers) Get(name string) (*Server, bool) {
	s, ok := srvs.mp[name]
	return s, ok
}

func (srvs *Servers) List() []*Server {
	var ret []*Server
	for _, srv := range srvs.mp {
		ret = append(ret, srv)
	}
	return ret
}

func NewServers() *Servers {
	return &Servers{mp: make(map[string]*Server)}
}

func (s *Server) Start() error {
	s.Lock()
	defer s.Unlock()
	var haveIPv4 bool
	var haveIPv6 bool

	if s.name == "" {
		return fmt.Errorf("invalid server config")
	}

	s.done = make(chan struct{})

	cmd := exec.Command("virsh", "metadata", "--domain", s.name, "--uri", "http://simplecloud.ru/", "--live")
	buf, err := cmd.Output()
	if err != nil {
		return err
	}

	s.metadata = Metadata{}
	if err = xml.Unmarshal(buf, &s.metadata); err != nil {
		return err
	}

	iface, err := net.InterfaceByName(master_iface)
	if err != nil {
		return err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}
	var peer string

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

	var cmds []*exec.Cmd
	for _, addr := range s.metadata.Network.IP {
		switch addr.Family {
		case "ipv4":
			if addr.Host == "false" {
				haveIPv4 = true
			} else if addr.Peer != "" {
				cmds = append(cmds, exec.Command("ipset", "-!", "add", "prevent_spoofing", addr.Address+"/"+addr.Prefix+","+"tap"+s.name))
			}
		case "ipv6":
			if addr.Host == "false" {
				cmds = append(cmds, exec.Command("ipset", "-!", "add", "prevent6_spoofing", addr.Address+","+"tap"+s.name))
				haveIPv6 = true
			}
		}
	}

	metaIP := cleanExists(s.name, s.metadata.Network.IP)
	for _, addr := range metaIP {
		if addr.Family == "ipv4" && addr.Host == "true" {
			if addr.Peer != "" {
				cmds = append(cmds, exec.Command("ip", "-4", "a", "replace", peer, "peer", addr.Address+"/"+addr.Prefix, "dev", "tap"+s.name))
			} else {
				cmds = append(cmds, exec.Command("ip", "-4", "a", "replace", addr.Address+"/"+addr.Prefix, "dev", "tap"+s.name))
			}
		}
	}

	if haveIPv4 {
		cmds = append(cmds, exec.Command("sysctl", "-w", "net.ipv4.conf.tap"+s.name+".proxy_arp=1"))
	}

	for _, addr := range metaIP {
		if addr.Family == "ipv6" && addr.Host == "true" {
			cmds = append(cmds, exec.Command("ip", "-6", "a", "replace", addr.Address+"/"+addr.Prefix, "dev", "tap"+s.name))
			cmds = append(cmds, exec.Command("ip", "-6", "r", "replace", addr.Address+"/"+addr.Prefix, "dev", "tap"+s.name, "proto", "static", "table", "200"))
		}
	}

	l.Info(fmt.Sprintf("%s wait for iface tap%s up to 10s", s.name, s.name))
	iface_ready := false
	for i := 0; i < 10; i++ {
		if _, err := net.InterfaceByName("tap" + s.name); err == nil {
			iface_ready = true
			break
		}
		time.Sleep(1 * time.Second)
	}

	if !iface_ready {
		return fmt.Errorf("%s timeout waiting for iface tap%s", s.name, s.name)
	}

	for _, cmd := range cmds {
		l.Info(fmt.Sprintf("%s exec %s", s.name, strings.Join(cmd.Args, " ")))
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("%s Failed to run cmd %s: %s", s.name, strings.Join(cmd.Args, " "), err)
		}
	}

	if haveIPv4 {
		l.Info(s.name + " ListenAndServeUDPv4")
		go s.ListenAndServeUDPv4()
	}

	if haveIPv6 {
		l.Info(s.name + " ListenAndServeICMPv6")
		go s.ListenAndServeICMPv6()
	}

	return nil
}

func (s *Server) Stop(cleanup bool) (err error) {
	s.Lock()
	defer s.Unlock()
	close(s.done)

	time.Sleep(2 * time.Second)

	l.Info(fmt.Sprintf("%s shutdown ipv4 conn", s.name))
	s.ipv4conn.Close()

	l.Info(fmt.Sprintf("%s shutdown ipv6 conn", s.name))
	s.ipv6conn.Close()

	s.downtime = time.Now()

	if cleanup {
		var cmds []*exec.Cmd
		for _, addr := range s.metadata.Network.IP {
			if addr.Family == "ipv4" && addr.Host == "true" {
				if addr.Peer != "" {
					cmds = append(cmds, exec.Command("ipset", "-!", "del", "prevent_spoofing", addr.Address+"/"+addr.Prefix+","+"tap"+s.name))
				}
			}
		}
		for _, addr := range s.metadata.Network.IP {
			if addr.Family == "ipv6" && addr.Host == "true" {
				cmds = append(cmds, exec.Command("ipset", "-!", "del", "prevent6_spoofing", addr.Address+"/"+addr.Prefix+","+"tap"+s.name))
			}
		}

		for _, cmd := range cmds {
			l.Info(fmt.Sprintf("%s exec %s", s.name, strings.Join(cmd.Args, " ")))
			if err = cmd.Run(); err != nil {
				return fmt.Errorf("Failed to run cmd %s: %s", cmd, err)
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
