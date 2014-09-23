package tcp

import (
	"encoding/binary"
	"errors"
	"fmt"

	"../util"
)

type Option struct {
	Type   uint8
	Length uint8
	Data   []byte
}

func (o Option) String() string {
	switch o.Type {
	case 1:
		return "NOP"
	case 8:
		if len(o.Data) == 8 {
			return fmt.Sprintf("OPT:%v/%v",
				binary.BigEndian.Uint32(o.Data[:4]),
				binary.BigEndian.Uint32(o.Data[4:8]))
		}
	}
	return fmt.Sprintf("Option(%v:%v)", o.Type, o.Data)
}

var lotsOfZeros [1024]byte

type TCP struct {
	Src        uint16
	Dst        uint16
	Seq        uint32
	Ack        uint32
	DataOffset uint8
	FIN        bool
	SYN        bool
	RST        bool
	PSH        bool
	ACK        bool
	URG        bool
	ECE        bool
	CWR        bool
	NS         bool

	WinSize  uint16
	Checksum uint16
	Urgent   uint16
	Options  []Option
	Data     []byte
}

func (t *TCP) Len() (n uint16) {
	var optlen int
	var padding []byte
	for _, o := range t.Options {
		switch o.Type {
		case 0, 1:
			optlen += 1
		default:
			optlen += 2 + len(o.Data)
		}
	}

	padding = lotsOfZeros[:optlen%4]

	if t.DataOffset == 0 {
		n = uint16(20 + int(uint8((len(padding)+optlen+20)/4))*4)
	} else {
		n = uint16(20 + int(t.DataOffset)*4)
	}
	return n
}

func (t *TCP) Marshal() ([]byte, error) {
	var optlen int
	var padding []byte
	for _, o := range t.Options {
		switch o.Type {
		case 0, 1:
			optlen += 1
		default:
			optlen += 2 + len(o.Data)
		}
	}

	padding = lotsOfZeros[:optlen%4]
	t.DataOffset = uint8((len(padding) + optlen + 20) / 4)

	data := make([]byte, t.Len())
	binary.BigEndian.PutUint16(data, uint16(t.Src))
	binary.BigEndian.PutUint16(data[2:], uint16(t.Dst))
	binary.BigEndian.PutUint32(data[4:], t.Seq)
	binary.BigEndian.PutUint32(data[8:], t.Ack)
	binary.BigEndian.PutUint16(data[12:], t.offsetflags())
	binary.BigEndian.PutUint16(data[14:], t.WinSize)
	binary.BigEndian.PutUint16(data[18:], t.Urgent)
	start := 20
	for _, o := range t.Options {
		data[start] = o.Type
		switch o.Type {
		case 0, 1:
			start++
		default:
			data[start+1] = o.Length
			copy(data[start+2:start+len(o.Data)+2], o.Data)
			start += int(o.Length)
		}
	}
	copy(data[start:], padding)
	if t.Checksum == 0 {
		data[16] = 0
		data[17] = 0
		t.Checksum = util.Checksum(data)
	}
	binary.BigEndian.PutUint16(data[16:], t.Checksum)
	copy(data[start+len(padding):], t.Data)
	return data, nil
}

func (t *TCP) Unmarshal(data []byte) (err error) {
	if len(data) < 20 {
		return errors.New("The []byte is too short to unmarshal a full TCP message.")
	}
	t.Src = binary.BigEndian.Uint16(data[:2])
	t.Dst = binary.BigEndian.Uint16(data[2:4])
	t.Seq = binary.BigEndian.Uint32(data[4:8])
	t.Ack = binary.BigEndian.Uint32(data[8:12])
	t.DataOffset = data[12] >> 4
	t.FIN = data[13]&0x01 != 0
	t.SYN = data[13]&0x02 != 0
	t.RST = data[13]&0x04 != 0
	t.PSH = data[13]&0x08 != 0
	t.ACK = data[13]&0x10 != 0
	t.URG = data[13]&0x20 != 0
	t.ECE = data[13]&0x40 != 0
	t.CWR = data[13]&0x80 != 0
	t.NS = data[12]&0x01 != 0
	t.WinSize = binary.BigEndian.Uint16(data[14:16])
	t.Checksum = binary.BigEndian.Uint16(data[16:18])
	t.Urgent = binary.BigEndian.Uint16(data[18:20])

	if t.DataOffset < 5 {
		return fmt.Errorf("Invalid TCP data offset %d < 5", t.DataOffset)
	}

	dataStart := int(t.DataOffset) * 4
	if dataStart > len(data) {
		return errors.New("TCP data offset greater than packet length")
	}

	t.Data = make([]byte, len(data[dataStart:]))
	copy(t.Data, data[dataStart:])

	options := data[20:dataStart]
	for len(options) > 0 {
		t.Options = append(t.Options, Option{Type: options[0]})
		opt := &t.Options[len(t.Options)-1]
		switch opt.Type {
		case 0: // End of options
			opt.Length = 1
			break
		case 1: // 1 byte padding
			opt.Length = 1
		default:
			opt.Length = options[1]
			if opt.Length < 2 {
				return fmt.Errorf("Invalid TCP option length %d < 2", opt.Length)
			} else if int(opt.Length) > len(options) {
				return fmt.Errorf("Invalid TCP option length %d exceeds remaining %d bytes", opt.Length, len(options))
			}
			opt.Data = options[2:opt.Length]
		}
		options = options[opt.Length:]
	}

	return nil
}

func (t *TCP) offsetflags() uint16 {
	f := uint16(t.DataOffset) << 12
	if t.FIN {
		f |= 0x0001
	}
	if t.SYN {
		f |= 0x0002
	}
	if t.RST {
		f |= 0x0004
	}
	if t.PSH {
		f |= 0x0008
	}
	if t.ACK {
		f |= 0x0010
	}
	if t.URG {
		f |= 0x0020
	}
	if t.ECE {
		f |= 0x0040
	}
	if t.CWR {
		f |= 0x0080
	}
	if t.NS {
		f |= 0x0100
	}
	return f
}
