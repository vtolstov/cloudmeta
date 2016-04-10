package main

import (
	"os"
	"os/exec"
	"path/filepath"
)

var (
	systemdService = []byte(`[Unit]
Description=cloudmeta
After=syslog.target

[Service]
Type=simple
ExecStart=/usr/bin/cloudmeta
Restart=on-abort
StartLimitInterval=10s
StartLimitBurst=3
[Install]
WantedBy=multi-user.target
`)
)

func installService() error {
	//systemd
	for _, osname := range []string{"exherbo", "centos", "redhat"} {
		if _, err := os.Stat(filepath.Join("/etc", osname+"-release")); err == nil {
			f, err := os.OpenFile("/usr/lib/systemd/system/cloudmeta.service", os.O_WRONLY|os.O_TRUNC|os.O_CREATE, os.FileMode(0644))
			if err != nil {
				return err
			}
			defer f.Close()
			if _, err = f.Write(systemdService); err != nil {
				return err
			}
			cmd := exec.Command("systemctl", "enable", "cloudmeta")
			if err = cmd.Run(); err != nil {
				return err
			}
		}
	}
	return nil
}
