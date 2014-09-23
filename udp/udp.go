package udp

import (
	"encoding/binary"
	"errors"
	"net"
)

type UDP struct {
	Src      uint16
	Dst      uint16
	Length   uint16
	Checksum uint16
	Data     []byte
}

func (p *UDP) Len() (n uint16) {
	if p.Data != nil {
		return uint16(8 + len(p.Data))
	}
	return uint16(8)
}

func UDPv4PseudoHeader(src, dst net.IP, nextHeader int, length uint16) []byte {
	b := make([]byte, 12)
	copy(b[0:3], src.To4())
	copy(b[3:7], dst.To4())
	b[8] = byte(0)
	b[9] = byte(nextHeader)
	binary.BigEndian.PutUint16(b[10:12], length)
	return b
}

func (p *UDP) Marshal() ([]byte, error) {
	data := make([]byte, int(p.Len()))
	binary.BigEndian.PutUint16(data[:2], p.Src)
	binary.BigEndian.PutUint16(data[2:4], p.Dst)
	binary.BigEndian.PutUint16(data[4:6], p.Length)
	binary.BigEndian.PutUint16(data[6:8], p.Checksum)
	copy(data[8:], p.Data)
	return data, nil
}

func (p *UDP) Unmarshal(data []byte) error {
	if len(data) < 8 {
		return errors.New("The []byte is too short to unmarshal a full UDP message.")
	}
	p.Src = binary.BigEndian.Uint16(data[:2])
	p.Dst = binary.BigEndian.Uint16(data[2:4])
	p.Length = binary.BigEndian.Uint16(data[4:6])
	p.Checksum = binary.BigEndian.Uint16(data[6:8])
	if p.Length > 8 {
		p.Data = make([]byte, p.Length-8)
		copy(p.Data, data[8:])
	}
	return nil
}
