PWD := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

binary:
	GOPATH=$(PWD)/third_party/ go build -a -x  -o svirtnet
