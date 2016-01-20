package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

func getServerByIP(ip string) (*Server, error) {
	servers.Lock()
	defer servers.Unlock()
	for _, s := range servers.List() {
		for _, addr := range s.metadata.Config.Network.IP {
			if addr.Gateway == "false" && addr.Address == ip {
				return s, nil
			}
		}
	}
	return nil, fmt.Errorf("failed to get Server by IP")
}

func ListenAndServeTCPv4() {
	ipAddr := &net.TCPAddr{IP: net.IPv4zero, Port: 80}
	conn, err := net.Listen("tcp", ipAddr.String())
	if err != nil {
		l.Info(err.Error())
		return
	}

	defer conn.Close()

	r := http.NewServeMux()
	r.HandleFunc("/", ServeHTTP)
	http.Handle("/", r)

	s := &http.Server{
		Addr:           ":80",
		Handler:        r,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	s.Serve(conn)
}

func ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var host string
	var port string
	var res *http.Response

	host, _, _ = net.SplitHostPort(r.RemoteAddr)
	s, err := getServerByIP(host)
	if err != nil {
		l.Info(fmt.Sprintf("err: %s %+v\n", err, r))
		w.WriteHeader(503)
		return
	}
	l.Info(fmt.Sprintf("%s http req: Host:%s RemoteAddr:%s URL:%s\n", s.name, r.Host, r.RemoteAddr, r.URL))

	u, _ := url.Parse(s.metadata.Config.CloudConfig.URL)
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
		l.Warning(fmt.Sprintf("%s http err: %s\n", s.name, err.Error()))
		w.WriteHeader(503)
		return
	}

	var addr net.IP

	for _, addr = range addrs {
		if addr.To4() == nil {
			break
		}
	}
	uri := path.Clean(r.URL.String())
	switch uri {
	case "/agent/log":
		req, _ := http.NewRequest("POST", s.metadata.Config.Agent.Log, r.Body)
		req.Header.Add("Content-Type", r.Header.Get("Content-Type"))
		//		req.Header.Add("Content-Length", r.Header.Get("Content-Length"))
		req.ContentLength = r.ContentLength
		httpClient.Do(req)
		w.Write([]byte(""))
	case "/2009-04-04":
		w.Write([]byte("meta-data\n"))
	case "/":
		w.Write([]byte("2009-04-04\nlatest\n"))
	case "/2009-04-04/meta-data", "/latest/meta-data":
		w.Write([]byte("public-hostname\nhostname\nlocal-hostname\ninstance-id\npublic-ipv4\npublic-keys\n"))
	case "/2009-04-04/meta-data/public-hostname", "/2009-04-04/meta-data/hostname", "/2009-04-04/meta-data/local-hostname", "/latest/meta-data/public-hostname", "/latest/meta-data/hostname", "/latest/meta-data/local-hostname":
		w.Write([]byte(s.name + "." + s.metadata.Config.Network.DomainName + "\n"))
	case "/2009-04-04/meta-data/local-ipv4":
		w.Write([]byte(""))
	case "/2009-04-04/meta-data/instance-id", "/latest/meta-data/instance-id":
		w.Write([]byte(s.name + "\n"))
	case "/2009-04-04/meta-data/public-ipv4", "/latest/meta-data/public-ipv4":
		w.Write([]byte(""))
	case "/2009-04-04/meta-data/public-keys", "/latest/meta-data/public-keys":
		w.Write([]byte("0=id_rsa\n"))
	case "/2009-04-04/meta-data/public-keys/0", "/latest/meta-data/public-keys/0":
		w.Write([]byte("openssh-key\n"))
	case "/2009-04-04/meta-data/public-keys/0/openssh-key", "/latest/meta-data/public-keys/0/openssh-key":
		req, _ := http.NewRequest("GET", s.metadata.Config.CloudConfig.URL, nil)
		req.URL = u
		req.URL.Host = net.JoinHostPort(addr.String(), port)
		req.Host = host
		res, err = httpClient.Do(req)
		if res != nil && res.Body != nil {
			defer res.Body.Close()
		}
		if res == nil && err != nil {
			l.Warning(fmt.Sprintf("%s http err: %s\n", s.name, err.Error()))
			w.Write([]byte("\n"))
			return
		}
		buf, err := ioutil.ReadAll(res.Body)
		if err != nil {
			l.Warning(fmt.Sprintf("%s http err: %s\n", s.name, err.Error()))
			w.Write([]byte("\n"))
			return
		}

		type User struct {
			Name   string   `yaml:"name,omitempty"`
			Passwd string   `yaml:"passwd,omitempty"`
			SSHKey []string `yaml:"ssh-authorized-keys,omitempty"`
		}

		type CloudConfig struct {
			AllowRootLogin bool   `yaml:"disable_root,omitempty"`
			AllowRootSSH   bool   `yaml:"ssh_pwauth,omitempty"`
			AllowResize    bool   `yaml:"resize_rootfs,omitempty"`
			Users          []User `yaml:"users,omitempty"`
		}
		var cloudconfig CloudConfig
		err = yaml.Unmarshal(buf, &cloudconfig)
		if err != nil {
			l.Warning(fmt.Sprintf("%s http err: %s\n", s.name, err.Error()))
			w.Write([]byte("\n"))
			return
		}
		w.Write([]byte(strings.Join(cloudconfig.Users[0].SSHKey, "\n") + "\n"))
	case "/openstack":
		w.Write([]byte("latest\n2013-04-04\n"))
	case "/openstack/latest", "/openstack/2013-04-04":
		w.Write([]byte("meta-data.json\nmeta_data.json\nuser-data\nuser_data\nvendor-data\nvendo_data\n"))
	case "/openstack/2013-04-04/password", "/openstack/latest/password":
		w.WriteHeader(200)
	case "/openstack/latest/meta-data.json", "/openstack/latest/meta_data.json", "/openstack/2013-04-04/meta_data.json":
		type openstackMetaData struct {
			Meta struct {
				Username  string `json:"username"`
				AdminPass string `json:"admin_pass"`
				UUID      string `json:"uuid"`
				Hostname  string `json:"hostname"`
			} `json:"meta"`
			UUID     string `json:"uuid"`
			Hostname string `json:"hostname"`
			SSHKey   struct {
				Root string `json:"root"`
			} `json:"public_keys,omitempty"`
		}
		metadata := &openstackMetaData{}
		metadata.Meta.Hostname = s.name + "." + s.metadata.Config.Network.DomainName
		metadata.Hostname = s.name + "." + s.metadata.Config.Network.DomainName

		uuid := "644e1dd7-2a7f-18fb-b8ed-ed78c3f92c2b"
		metadata.Meta.UUID = uuid
		metadata.UUID = uuid
		req, _ := http.NewRequest("GET", s.metadata.Config.CloudConfig.URL, nil)
		req.URL = u
		req.URL.Host = net.JoinHostPort(addr.String(), port)
		req.Host = host
		res, err = httpClient.Do(req)
		if res != nil && res.Body != nil {
			defer res.Body.Close()
		}
		if res == nil && err != nil {
			w.Write([]byte("{}"))
			return
		}
		buf, err := ioutil.ReadAll(res.Body)
		if err != nil {
			w.Write([]byte("{}"))
			return
		}

		type User struct {
			Name   string   `yaml:"name,omitempty"`
			Passwd string   `yaml:"passwd,omitempty"`
			SSHKey []string `yaml:"ssh-authorized-keys,omitempty"`
		}

		type CloudConfig struct {
			AllowRootLogin bool   `yaml:"disable_root,omitempty"`
			AllowRootSSH   bool   `yaml:"ssh_pwauth,omitempty"`
			AllowResize    bool   `yaml:"resize_rootfs,omitempty"`
			Users          []User `yaml:"users,omitempty"`
		}
		var cloudconfig CloudConfig
		err = yaml.Unmarshal(buf, &cloudconfig)
		if err != nil {
			w.Write([]byte("{}"))
			return
		}
		metadata.Meta.Username = cloudconfig.Users[0].Name
		metadata.Meta.AdminPass = cloudconfig.Users[0].Passwd
		metadata.SSHKey.Root = strings.Join(cloudconfig.Users[0].SSHKey, "\n")
		buf, err = json.Marshal(metadata)
		if err != nil {
			w.Write([]byte("{}"))
		} else {
			w.Write([]byte(buf))
		}
	case "/2009-04-04/user-data", "/latest/user-data", "/openstack/latest/user_data", "/openstack/latest/user-data", "/openstack/latest/vendor_data", "/openstack/latest/vendor-data":
		req, _ := http.NewRequest("GET", s.metadata.Config.CloudConfig.URL, nil)
		req.URL = u
		req.URL.Host = net.JoinHostPort(addr.String(), port)
		req.Host = host
		res, err = httpClient.Do(req)
		if res != nil && res.Body != nil {
			defer res.Body.Close()
		}
		if res == nil && err != nil {
			l.Warning(fmt.Sprintf("%s http err: %s\n", s.name, err.Error()))
			w.WriteHeader(503)
			return
		}
		io.Copy(w, res.Body)
	default:
		l.Info(fmt.Sprintf("http: %+v\n", r))
		w.WriteHeader(503)
	}
	return
}
