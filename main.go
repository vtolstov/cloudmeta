package main

import (
	"bufio"
	"flag"
	"io/ioutil"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

func init() {
	flag.Parse()
	servers = make(map[string]*Server, 1024)
}

var l *syslog.Writer
var master_iface string = "vlan1001"

func main() {
	var err error
	var buf []byte
	var data map[string]string
	l, err = syslog.Dial("", "", syslog.LOG_DAEMON|syslog.LOG_INFO, filepath.Base(os.Args[0]))
	if err != nil {
		log.Fatalf("Failed to connect to syslog: %s\n", err.Error())
		os.Exit(1)
	}
	defer l.Close()

	if buf, err = ioutil.ReadFile("/etc/svirtnet.yml"); err == nil {
		if err = yaml.Unmarshal(buf, &data); err == nil {
			master_iface = data["interface"]
		}
	}

	l.Info("ListenAndServeTCPv4")
	go ListenAndServeTCPv4()

	go func() {
		cmd := exec.Command("virsh", "list", "--name", "--all")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			l.Info(err.Error())
			os.Exit(1)
		}
		defer stdout.Close()
		if err = cmd.Start(); err != nil {
			l.Info(err.Error())
			os.Exit(1)
		}
		br := bufio.NewReader(stdout)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				break
			}
			name := strings.TrimSpace(line)
			if name != "" {
				srvmutex.Lock()
				if _, ok := servers[name]; !ok {
					servers[name] = &Server{name: name}
					l.Info(name + " start serving")
					go servers[name].Start()
				}
				srvmutex.Unlock()
			}
		}
		if err := cmd.Wait(); err != nil {
			l.Info(err.Error())
			os.Exit(1)
		}
	}()

	for {
		cmd := exec.Command("virsh", "event", "--loop", "--event", "lifecycle")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			l.Info(err.Error())
			time.Sleep(5 * time.Second)
			continue
		}
		if err = cmd.Start(); err != nil {
			l.Info(err.Error())
			time.Sleep(5 * time.Second)
			continue
		}
		br := bufio.NewReader(stdout)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				break
			}
			fields := strings.Fields(line) // event 'lifecycle' for domain 44253: Started Booted
			name := strings.TrimRight(fields[4], ":")
			events := fields[5:]
			if strings.Index(strings.Join(events, " "), "Started") > 0 {
				srvmutex.Lock()
				if _, ok := servers[name]; !ok {
					servers[name] = &Server{name: name}
					go servers[name].Start()
					l.Info(name + " start serving")
				}
				srvmutex.Unlock()
			} else if strings.Index(strings.Join(events, " "), "Stopped") > 0 {
				srvmutex.Lock()
				if s, ok := servers[name]; ok {
					s.Stop()
					l.Info(name + " stop serving")
					delete(servers, name)
				}
				srvmutex.Unlock()
			}
		}
	}
}
