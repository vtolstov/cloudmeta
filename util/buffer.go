package util

import (
	"bytes"
)

type Buffer struct{ bytes.Buffer }

func NewBuffer(buf []byte) *Buffer {
	b := new(Buffer)
	b.Buffer = *bytes.NewBuffer(buf)
	return b
}

func (b *Buffer) Len() uint16 {
	return uint16(b.Buffer.Len())
}

func (b *Buffer) Marshal() (data []byte, err error) {
	return b.Buffer.Bytes(), nil
}

func (b *Buffer) Unmarshal(data []byte) error {
	b.Buffer.Reset()
	_, err := b.Buffer.Write(data)
	return err
}
