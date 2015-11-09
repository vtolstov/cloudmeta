package main

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

var metadataMap map[string]func(w http.ResponseWriter, r *http.Request)

func init() {
	metadataMap = make(map[string]func(w http.ResponseWriter, r *http.Request))
	metadataMap["/"] = MetadataHandler
	metadataMap["/2009-04-04"] = Ec2Handler
	metadataMap["/latest"] = Ec2Handler
	metadataMap["/openstack"] = OpenstackHandler
	metadataMap["/metadata"] = DigitalOceanHandler
}

func getServerByIP(ip string) (*Server, error) {
	for _, s := range servers {
		if s.metadata == nil {
			continue
		}
		for _, addr := range s.metadata.Network.IP {
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

	httpconn = conn
	defer conn.Close()

	r := mux.NewRouter()
	for k, v := range metadataMap {
		r.HandleFunc(k, v)
	}
	http.Handle("/", r)

	s := &http.Server{
		Addr:           ":80",
		Handler:        r,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	s.Serve(httpconn)
}

func MetadataHandler(w http.ResponseWriter, r *http.Request) {
	for k, _ := range metadataMap {
		w.Write([]byte(k[1:]))
		w.Write([]byte("\n"))
	}
}
