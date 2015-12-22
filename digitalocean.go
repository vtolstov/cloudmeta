package main

import (
	"net/http"
	"path"
)

type DigitalOceanV1Metadata struct {
	DropletID  int64    `json:"droplet_id"`
	Hostname   string   `json:"hostname"`
	VendorData string   `json:"vendor_data"`
	PublicKeys []string `json:"public_keys"`
	Region     string   `json:"region"`
	Interfaces struct {
		private []struct {
			ipv4 struct {
				Address string `json:"ip_address"`
				Netmask string `json:"netmask"`
				Gateway string `json:"gateway"`
			}
			Mac  string
			Type string
		} `json:"private"`
		public []struct {
			IPv4 struct {
				Address string `json:"ip_address"`
				Netmask string `json:"netmask"`
				Gateway string `json:"gateway"`
			} `json:"ipv4"`
			IPv6 struct {
				Address string `json:"ip_address"`
				CIDR    int    `json:"cird"`
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
		nameservers []string `json:"nameservers"`
	} `json:"dns"`
}

func DigitalOceanHandler(w http.ResponseWriter, r *http.Request) {
	u := path.Clean(r.URL.String())
	switch u {
	case "/metadata/v1.json":
		resData := struct {
			DropletID  int64    `json:"droplet_id"`
			Hostname   string   `json:"hostname"`
			VendorData string   `json:"vendor_data"`
			PublicKeys []string `json:"public_keys"`
			Region     string   `json:"region"`
			Interfaces struct {
				private []struct {
					ipv4 struct {
						Address string `json:"ip_address"`
						Netmask string `json:"netmask"`
						Gateway string `json:"gateway"`
					}
					Mac  string
					Type string
				} `json:"private"`
				public []struct {
					IPv4 struct {
						Address string `json:"ip_address"`
						Netmask string `json:"netmask"`
						Gateway string `json:"gateway"`
					} `json:"ipv4"`
					IPv6 struct {
						Address string `json:"ip_address"`
						CIDR    int    `json:"cird"`
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
				nameservers []string `json:"nameservers"`
			} `json:"dns"`
		}{}
	}
}
