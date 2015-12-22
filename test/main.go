package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/antonholmquist/jason"
	"github.com/codegangsta/negroni"
)

var js = []byte(`{
  "droplet_id":2756294,
  "hostname":"sample-droplet",
  "vendor_data":"#cloud-config\ndisable_root: false\nmanage_etc_hosts: true\n\ncloud_config_modules:\n - ssh\n - set_hostname\n - [ update_etc_hosts, once-per-instance ]\n\ncloud_final_modules:\n - scripts-vendor\n - scripts-per-once\n - scripts-per-boot\n - scripts-per-instance\n - scripts-user\n",
  "public_keys":["ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcbi6cygCUmuNlB0KqzBpHXf7CFYb3VE4pDOf/RLJ8OFDjOM+fjF83a24QktSVIpQnHYpJJT2pQMBxD+ZmnhTbKv+OjwHSHwAfkBullAojgZKzz+oN35P4Ea4J78AvMrHw0zp5MknS+WKEDCA2c6iDRCq6/hZ13Mn64f6c372JK99X29lj/B4VQpKCQyG8PUSTFkb5DXTETGbzuiVft+vM6SF+0XZH9J6dQ7b4yD3sOder+M0Q7I7CJD4VpdVD/JFa2ycOS4A4dZhjKXzabLQXdkWHvYGgNPGA5lI73TcLUAueUYqdq3RrDRfaQ5Z0PEw0mDllCzhk5dQpkmmqNi0F sammy@digitalocean.com"],
  "region":"nyc3",
  "interfaces":{
    "private":[
      {
        "ipv4":{
          "ip_address":"10.132.255.113",
          "netmask":"255.255.0.0",
          "gateway":"10.132.0.1"
        },
        "mac":"04:01:2a:0f:2a:02",
        "type":"private"
      }
    ],
    "public":[
      {
        "ipv4":{
          "ip_address":"104.131.20.105",
          "netmask":"255.255.192.0",
          "gateway":"104.131.0.1"
        },
        "ipv6":{
          "ip_address":"2604:A880:0800:0010:0000:0000:017D:2001",
          "cidr":64,
          "gateway":"2604:A880:0800:0010:0000:0000:0000:0001"
        },
        "mac":"04:01:2a:0f:2a:01",
        "type":"public"}
    ]
  },
  "floating_ip": {
    "ipv4": {
      "active": false
    }
  },
  "dns":{
    "nameservers":[
      "2001:4860:4860::8844",
      "2001:4860:4860::8888",
      "8.8.8.8"
    ]
  }
}
`)

type DigitalOceanMeta struct {
	DropletID  int64    `json:"droplet_id"`
	Hostname   string   `json:"hostname"`
	VendorData string   `json:"vendor_data"`
	PublicKeys []string `json:"public_keys"`
	Region     string   `json:"region"`
	Interfaces struct {
		Private []struct {
			IPv4 struct {
				Address string `json:"ip_address"`
				Netmask string `json:"netmask"`
				Gateway string `json:"gateway"`
			}
			Mac  string `json:"mac"`
			Type string `json:"type"`
		} `json:"private"`
		Public []struct {
			IPv4 struct {
				Address string `json:"ip_address"`
				Netmask string `json:"netmask"`
				Gateway string `json:"gateway"`
			} `json:"ipv4"`
			IPv6 struct {
				Address string `json:"ip_address"`
				CIDR    int    `json:"cidr"`
				Gateway string `json:"gateway"`
			} `json:"ipv6"`
			Mac  string `json:"mac"`
			Type string `json:"type"`
		} `json:"public"`
	} `json:"interfaces"`
	FloatingIP struct {
		IPv4 struct {
			Active bool `json:"active"`
		} `json:"ipv4"`
	} `json:"floating_ip"`
	DNS struct {
		Nameservers []string `json:"nameservers"`
	} `json:"dns"`
}

func main() {
	data := DigitalOceanMeta{}
	json.Unmarshal(js, &data)
	r := negroni.New()
	s := negroni.NewStatic(&Fs{data: nil})
	s.Prefix = "/metadata"
	r.Use(s)
	r.Run(":8080")
}

type MetaType int

const (
	MetaTypeInvalid MetaType = iota
	MetaTypeDigitalOcean
	MetaTypeEc2
	MetaTypeOpenstack
)

type Fs struct {
	data *jason.Object
}

type File struct {
	name  string
	data  *jason.Object
	value []byte
	at    int64
}

type FileInfo struct {
	data *jason.Object
	name string
}

func (fi *FileInfo) Sys() interface{} {
	return nil
}

func (fi *FileInfo) Size() int64 {
	return 0
}

func (fi *FileInfo) Name() string {
	return fi.name
}

func (fi *FileInfo) Mode() os.FileMode {
	if strings.HasSuffix(fi.name, "/") {
		return os.FileMode(0755) | os.ModeDir
	}
	return os.FileMode(0644)
}

func (fi *FileInfo) IsDir() bool {
	return false
}

func (fi *FileInfo) ModTime() time.Time {
	return time.Now()
}

func (f *File) Close() error {
	return nil
}

func delete_empty(s []string) []string {
	var r []string
	for _, str := range s {
		if str != "" {
			r = append(r, str)
		}
	}
	return r
}

func (f *File) Read(b []byte) (int, error) {
	log.Printf("read %s %d %d\n", f.name, len(b), f.at)
	var buffer []byte

	if f.at > int64(len(f.value)) {
		log.Printf("eof\n")
		return 0, io.EOF
	}

	if len(f.value) > 0 {
		buffer = make([]byte, len(f.value[f.at:]))
		copy(buffer, f.value[f.at:])
		goto read
	}

	switch {
	case f.name == "/v1.json":
		buffer = []byte(f.data.String())
	case strings.HasPrefix(f.name, "/v1/"):
		name := strings.TrimPrefix(f.name, "/v1")
		val, err := f.data.GetInterface(delete_empty(strings.Split(name, "/"))...)
		if err != nil {
			log.Printf("errrrr %s\n", err.Error())
			return 0, err
		}
		buffer = []byte(fmt.Sprintf("%s", val))
	}

	f.value = make([]byte, len(buffer))
	copy(f.value, buffer)

read:
	r := bytes.NewReader(buffer)
	n, err := r.Read(b)
	f.at += int64(n)
	return n, err
}

func (f *File) Readdir(count int) ([]os.FileInfo, error) {
	return nil, nil
}

func (f *File) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case os.SEEK_SET:
		f.at = offset
	case os.SEEK_CUR:
		f.at += offset
	case os.SEEK_END:
		f.at = int64(len(f.value)) + offset
	}
	return f.at, nil

}

func (f *File) Stat() (os.FileInfo, error) {
	log.Printf("stat %s\n", f.name)
	return &FileInfo{name: f.name, data: f.data}, nil
}

func (fs *Fs) Open(name string) (http.File, error) {
	log.Printf("open %s\n", name)
	obj, _ := jason.NewObjectFromBytes(js)
	return &File{name: name, data: obj}, nil
}
