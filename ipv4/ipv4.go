package ipv4

import (
	"encoding/binary"
	"errors"
	"net"

	"../udp"
	"../util"
)

const (
	Type_ICMPv4 = 0x01
	Type_TCP    = 0x06
	Type_UDP    = 0x11
)

type IPv4 struct {
	Version        uint8 //4-bits
	IHL            uint8 //4-bits
	DSCP           uint8 //6-bits
	ECN            uint8 //2-bits
	Length         uint16
	Id             uint16
	Flags          uint16 //3-bits
	FragmentOffset uint16 //13-bits
	TTL            uint8
	Protocol       uint8
	Checksum       uint16
	Src            net.IP
	Dst            net.IP
	Options        util.Buffer
	Data           util.Message
}

/*
func UDPv6PseudoHeader(src, dst net.IP, nextHeader int, Length uint16) []byte {
  b := make([]byte, 2*net.IPv4len+4)
  copy(b[:net.IPv4len], src)
  copy(b[net.IPv4len:], dst)
  b[2*net.IPv4len+2] = byte(nextHeader)
  binary.BigEndian.PutUint16(b[2*net.IPv4len+3], Length)
  return b
}
*/

func New() *IPv4 {
	ip := new(IPv4)
	ip.Src = make([]byte, net.IPv4len)
	ip.Dst = make([]byte, net.IPv4len)
	ip.Options = *new(util.Buffer)
	return ip
}

func (i *IPv4) Len() (n uint16) {
	i.IHL = 5
	if i.Data != nil {
		return uint16(i.IHL*4) + i.Data.Len()
	}
	return uint16(i.IHL * 4)
}

func (i *IPv4) Marshal() (data []byte, err error) {
	data = make([]byte, int(i.Len()))
	b := make([]byte, 0)
	n := 0

	var ihl uint8 = (i.Version << 4) + i.IHL
	data[n] = ihl
	n += 1
	var ecn uint8 = (i.DSCP << 2) + i.ECN
	data[n] = ecn
	n += 1
	binary.BigEndian.PutUint16(data[n:], i.Length)
	n += 2
	binary.BigEndian.PutUint16(data[n:], i.Id)
	n += 2
	var flg uint16 = (i.Flags << 13) + i.FragmentOffset
	binary.BigEndian.PutUint16(data[n:], flg)
	n += 2
	data[n] = i.TTL
	n += 1
	data[n] = i.Protocol
	n += 1
	binary.BigEndian.PutUint16(data[n:], i.Checksum)
	n += 2

	copy(data[n:], i.Src.To4())
	n += 4 // Underlying rep can be 16 bytes.
	copy(data[n:], i.Dst.To4())
	n += 4 // Underlying rep can be 16 bytes.

	b, err = i.Options.Marshal()
	copy(data[n:], b)
	n += len(b)

	if i.Data != nil {
		b, err = i.Data.Marshal()
		if err != nil {
			return
		}
		copy(data[n:], b)
		n += len(b)
	}
	return
}

func (i *IPv4) Unmarshal(data []byte) error {
	if len(data) < 20 {
		return errors.New("The []byte is too short to unmarshal a full IPv4 message.")
	}
	n := 0

	var ihl uint8
	ihl = data[n]
	i.Version = ihl >> 4
	i.IHL = ihl & 0x0f
	n += 1

	var ecn uint8
	ecn = data[n]
	i.DSCP = ecn >> 2
	i.ECN = ecn & 0x03
	n += 1

	i.Length = binary.BigEndian.Uint16(data[n:])
	n += 2
	i.Id = binary.BigEndian.Uint16(data[n:])
	n += 2

	var flg uint16
	flg = binary.BigEndian.Uint16(data[n:])
	i.Flags = flg >> 13
	i.FragmentOffset = flg & 0x1fff
	n += 2

	i.TTL = data[n]
	n += 1
	i.Protocol = data[n]
	n += 1
	i.Checksum = binary.BigEndian.Uint16(data[n:])
	n += 2
	i.Src = data[n : n+4]
	n += 4
	i.Dst = data[n : n+4]
	n += 4

	i.Options.Unmarshal(data[n:int(i.IHL*4)])
	n += int(i.IHL*4) - n

	switch i.Protocol {
	case Type_UDP:
		i.Data = &udp.UDP{}
	default:
		i.Data = new(util.Buffer)
	}
	return i.Data.Unmarshal(data[n:])
}
