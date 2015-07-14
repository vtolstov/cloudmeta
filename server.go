package main

import (
	"encoding/xml"
	"errors"
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

	"github.com/vtolstov/svirtnet/internal/golang.org/x/net/ipv4"
	"github.com/vtolstov/svirtnet/internal/golang.org/x/net/ipv6"

	"github.com/vtolstov/svirtnet/internal/github.com/alexzorin/libvirt-go"
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
	NameServer []string `xml:"nameserver,omitempty"`
	DomainName string   `xml:"domainname,omitempty"`
	IP         []IP     `xml:"ip"`
}

type ISO struct {
	Disks []ISODisk `xml:"disk"`
}

type ISODisk struct {
	Name   string `xml:"driver->name,attr"`
	Type   string `xml:"driver->type,attr"`
	Source string `xml:"source->url,attr"`
	Target string `xml:"target->name,attr"`
}

type Metadata struct {
	Network     Network     `xml:"network"`
	CloudConfig CloudConfig `xml:"cloud-config"`
	ISO         ISO         `xml:"iso,omitempty"`
}

var httpconn net.Listener

type Server struct {
	// shutdown flag
	shutdown bool

	// domain name
	name string

	// domain metadata
	metadata *Metadata

	// DHCPv4 conn
	ipv4conn *ipv4.RawConn

	// RA conn
	ipv6conn *ipv6.PacketConn

	// thread safe
	sync.RWMutex
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

	if s.name == "" {
		return errors.New("invalid server config")
	}

	virconn = getVirConn()
	domain, err = virconn.LookupDomainByName(s.name)
	if err != nil {
		l.Info("failed to lookup to libvirt: " + err.Error())
		return err
	}

	buf, err = domain.GetMetadata(libvirt.VIR_DOMAIN_METADATA_ELEMENT, "http://simplecloud.ru/", libvirt.VIR_DOMAIN_MEM_LIVE)
	if err != nil {
		l.Info("failed to get metadata from libvirt: " + err.Error())
		return err
	}
	s.metadata = &Metadata{}
	if err = xml.Unmarshal([]byte(buf), s.metadata); err != nil {
		l.Info("failed to get unmarshal xml from libvirt: " + err.Error())
		return err
	}

	if len(s.metadata.Network.NameServer) == 0 {
		s.metadata.Network.NameServer = []string{"8.8.8.8"}
	}
	if s.metadata.Network.DomainName == "" {
		s.metadata.Network.DomainName = "simplecloud.club"
	}

	iface, err := net.InterfaceByName(master_iface)
	if err != nil {
		l.Info("failed to get data from master_iface: " + err.Error())
		return err
	}

	addrs, err := iface.Addrs()
	if err != nil {
		l.Info("failed to get ifaces: " + err.Error())
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
		if addr.Family == "ipv4" && addr.Host == "true" && addr.Peer != "" {
			cmds = append(cmds, exec.Command("ipset", "-!", "add", "prevent_spoofing", addr.Address+"/"+addr.Prefix+","+"tap"+s.name))
		}
		if addr.Family == "ipv6" && addr.Host == "false" {
			cmds = append(cmds, exec.Command("ipset", "-!", "add", "prevent6_spoofing", addr.Address+","+"tap"+s.name))
		}
	}

	metaIP := cleanExists(s.name, s.metadata.Network.IP)
	for _, addr := range metaIP {
		if addr.Family == "ipv4" && addr.Host == "true" {
			// TODO: use netlink
			if addr.Peer != "" {
				cmds = append(cmds, exec.Command("ip", "-4", "a", "add", peer, "peer", addr.Address+"/"+addr.Prefix, "dev", "tap"+s.name))
			} else {
				cmds = append(cmds, exec.Command("ip", "-4", "a", "add", addr.Address+"/"+addr.Prefix, "dev", "tap"+s.name))
			}
		}
	}

	cmds = append(cmds, exec.Command("sysctl", "-w", "net.ipv4.conf.tap"+s.name+".proxy_arp=1"))

	for _, addr := range metaIP {
		if addr.Family == "ipv6" && addr.Host == "true" {
			// TODO: use netlink
			cmds = append(cmds, exec.Command("ip", "-6", "a", "add", addr.Address+"/"+addr.Prefix, "dev", "tap"+s.name))
			cmds = append(cmds, exec.Command("ip", "-6", "r", "replace", addr.Address+"/"+addr.Prefix, "dev", "tap"+s.name, "proto", "static", "table", "200"))
		}
	}

	for _, cmd := range cmds {
		err = cmd.Run()
		if err != nil {
			l.Info(fmt.Sprintf("Failed to run cmd %s: %s", cmd, err))
			return fmt.Errorf("Failed to run cmd %s: %s", cmd, err)
		}
	}

	l.Info(s.name + " ListenAndServeUDPv4")
	go s.ListenAndServeUDPv4()

	l.Info(s.name + " ListenAndServeICMPv6")
	go s.ListenAndServeICMPv6()

	select {}
}

func (s *Server) Stop() (err error) {
	if s == nil {
		return nil
	}
	s.shutdown = true

	if s.ipv4conn != nil {
		s.ipv4conn.Close()
	}
	if s.ipv6conn != nil {
		s.ipv6conn.Close()
	}

	var cmds []*exec.Cmd
	if s.metadata != nil && len(s.metadata.Network.IP) > 0 {
		for _, addr := range s.metadata.Network.IP {
			if addr.Family == "ipv4" && addr.Host == "true" {
				// TODO: use netlink
				if addr.Peer != "" {
					cmds = append(cmds, exec.Command("ipset", "-!", "del", "prevent_spoofing", addr.Address+"/"+addr.Prefix+","+"tap"+s.name))
				}
			}
		}
		for _, addr := range s.metadata.Network.IP {
			if addr.Family == "ipv6" && addr.Host == "true" {
				// TODO: use netlink
				cmds = append(cmds, exec.Command("ipset", "-!", "del", "prevent6_spoofing", addr.Address+"/"+addr.Prefix+","+"tap"+s.name))
			}
		}

		for _, cmd := range cmds {
			err = cmd.Run()
			if err != nil {
				l.Info(fmt.Sprintf("Failed to run cmd %s: %s", cmd, err))
				return fmt.Errorf("Failed to run cmd %s: %s", cmd, err)
			}
		}
	}
	if s.metadata == nil {
		return nil
	}
	s.metadata = nil
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
