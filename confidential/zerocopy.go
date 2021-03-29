package confidential

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/Evanesco-Labs/ristretto255"
	"io"
	"math"
)

type ZeroCopySink struct {
	buf []byte
}

// tryGrowByReslice is a inlineable version of grow for the fast-case where the
// internal buffer only needs to be resliced.
// It returns the index where bytes should be written and whether it succeeded.
func (self *ZeroCopySink) tryGrowByReslice(n int) (int, bool) {
	if l := len(self.buf); n <= cap(self.buf)-l {
		self.buf = self.buf[:l+n]
		return l, true
	}
	return 0, false
}

const maxInt = int(^uint(0) >> 1)

// grow grows the buffer to guarantee space for n more bytes.
// It returns the index where bytes should be written.
// If the buffer can't grow it will panic with ErrTooLarge.
func (self *ZeroCopySink) grow(n int) int {
	// Try to grow by means of a reslice.
	if i, ok := self.tryGrowByReslice(n); ok {
		return i
	}

	l := len(self.buf)
	c := cap(self.buf)
	if c > maxInt-c-n {
		panic(ErrTooLarge)
	}
	// Not enough space anywhere, we need to allocate.
	buf := makeSlice(2*c + n)
	copy(buf, self.buf)
	self.buf = buf[:l+n]
	return l
}

func (self *ZeroCopySink) WriteBytes(p []byte) {
	data := self.NextBytes(uint64(len(p)))
	copy(data, p)
}

func (self *ZeroCopySink) Size() uint64 { return uint64(len(self.buf)) }

func (self *ZeroCopySink) NextBytes(n uint64) (data []byte) {
	m, ok := self.tryGrowByReslice(int(n))
	if !ok {
		m = self.grow(int(n))
	}
	data = self.buf[m:]
	return
}

// Backs up a number of bytes, so that the next call to NextXXX() returns data again
// that was already returned by the last call to NextXXX().
func (self *ZeroCopySink) BackUp(n uint64) {
	l := len(self.buf) - int(n)
	self.buf = self.buf[:l]
}

func (self *ZeroCopySink) WriteUint8(data uint8) {
	buf := self.NextBytes(1)
	buf[0] = data
}

func (self *ZeroCopySink) WriteByte(c byte) {
	self.WriteUint8(c)
}

func (self *ZeroCopySink) WriteBool(data bool) {
	if data {
		self.WriteByte(1)
	} else {
		self.WriteByte(0)
	}
}

func (self *ZeroCopySink) WriteUint16(data uint16) {
	buf := self.NextBytes(2)
	binary.LittleEndian.PutUint16(buf, data)
}

func (self *ZeroCopySink) WriteUint32(data uint32) {
	buf := self.NextBytes(4)
	binary.LittleEndian.PutUint32(buf, data)
}

func (self *ZeroCopySink) WriteUint64(data uint64) {
	buf := self.NextBytes(8)
	binary.LittleEndian.PutUint64(buf, data)
}

func (self *ZeroCopySink) WriteInt64(data int64) {
	self.WriteUint64(uint64(data))
}

func (self *ZeroCopySink) WriteInt32(data int32) {
	self.WriteUint32(uint32(data))
}

func (self *ZeroCopySink) WriteInt16(data int16) {
	self.WriteUint16(uint16(data))
}

func (self *ZeroCopySink) WriteVarBytes(data []byte) (size uint64) {
	l := uint64(len(data))
	size = self.WriteVarUint(l) + l

	self.WriteBytes(data)
	return
}

func (self *ZeroCopySink) WriteString(data string) (size uint64) {
	return self.WriteVarBytes([]byte(data))
}

func (self *ZeroCopySink) WriteVarUint(data uint64) (size uint64) {
	buf := self.NextBytes(9)
	if data < 0xFD {
		buf[0] = uint8(data)
		size = 1
	} else if data <= 0xFFFF {
		buf[0] = 0xFD
		binary.LittleEndian.PutUint16(buf[1:], uint16(data))
		size = 3
	} else if data <= 0xFFFFFFFF {
		buf[0] = 0xFE
		binary.LittleEndian.PutUint32(buf[1:], uint32(data))
		size = 5
	} else {
		buf[0] = 0xFF
		binary.LittleEndian.PutUint64(buf[1:], uint64(data))
		size = 9
	}

	self.BackUp(9 - size)
	return
}

func (self *ZeroCopySink) WriteScalar(s *ristretto255.Scalar) {
	b := ScalarToBytes(s)
	self.WriteVarBytes(b[:])
}

func (self *ZeroCopySink) WriteElement(e *ristretto255.Element) {
	b := ElementToBytes(e)
	self.WriteVarBytes(b[:])
}

// NewReader returns a new ZeroCopySink reading from b.
func NewZeroCopySink(b []byte) *ZeroCopySink {
	if b == nil {
		b = make([]byte, 0, 512)
	}
	return &ZeroCopySink{b}
}

func (self *ZeroCopySink) Bytes() []byte { return self.buf }

func (self *ZeroCopySink) Reset() { self.buf = self.buf[:0] }

var ErrTooLarge = errors.New("bytes.Buffer: too large")

// makeSlice allocates a slice of size n. If the allocation fails, it panics
// with ErrTooLarge.
func makeSlice(n int) []byte {
	// If the make fails, give a known error.
	defer func() {
		if recover() != nil {
			panic(bytes.ErrTooLarge)
		}
	}()
	return make([]byte, n)
}

var ErrIrregularData = errors.New("irregular data")

type ZeroCopySource struct {
	s   []byte
	off uint64 // current reading index
}

// Len returns the number of bytes of the unread portion of the
// slice.
func (self *ZeroCopySource) Len() uint64 {
	length := uint64(len(self.s))
	if self.off >= length {
		return 0
	}
	return length - self.off
}

func (self *ZeroCopySource) Pos() uint64 {
	return self.off
}

// Size returns the original length of the underlying byte slice.
// Size is the number of bytes available for reading via ReadAt.
// The returned value is always the same and is not affected by calls
// to any other method.
func (self *ZeroCopySource) Size() uint64 { return uint64(len(self.s)) }

// Read implements the io.ZeroCopySource interface.
func (self *ZeroCopySource) NextBytes(n uint64) (data []byte, eof bool) {
	m := uint64(len(self.s))
	end, overflow := SafeAdd(self.off, n)
	if overflow || end > m {
		end = m
		eof = true
	}
	data = self.s[self.off:end]
	self.off = end

	return
}

func (self *ZeroCopySource) Skip(n uint64) (eof bool) {
	m := uint64(len(self.s))
	end, overflow := SafeAdd(self.off, n)
	if overflow || end > m {
		end = m
		eof = true
	}
	self.off = end

	return
}

// ReadByte implements the io.ByteReader interface.
func (self *ZeroCopySource) NextByte() (data byte, eof bool) {
	if self.off >= uint64(len(self.s)) {
		return 0, true
	}

	b := self.s[self.off]
	self.off++
	return b, false
}

func (self *ZeroCopySource) NextUint8() (data uint8, eof bool) {
	var val byte
	val, eof = self.NextByte()
	return uint8(val), eof
}

func (self *ZeroCopySource) NextBool() (data bool, irregular bool, eof bool) {
	val, eof := self.NextByte()
	if val == 0 {
		data = false
	} else if val == 1 {
		data = true
	} else {
		data = true
		irregular = true
	}

	return
}

// Backs up a number of bytes, so that the next call to NextXXX() returns data again
// that was already returned by the last call to NextXXX().
func (self *ZeroCopySource) BackUp(n uint64) {
	self.off -= n
}

func (self *ZeroCopySource) NextUint16() (data uint16, eof bool) {
	var buf []byte
	buf, eof = self.NextBytes(2)
	if eof {
		return
	}

	return binary.LittleEndian.Uint16(buf), eof
}

func (self *ZeroCopySource) NextUint32() (data uint32, eof bool) {
	var buf []byte
	buf, eof = self.NextBytes(4)
	if eof {
		return
	}

	return binary.LittleEndian.Uint32(buf), eof
}

func (self *ZeroCopySource) NextUint64() (data uint64, eof bool) {
	var buf []byte
	buf, eof = self.NextBytes(8)
	if eof {
		return
	}

	return binary.LittleEndian.Uint64(buf), eof
}

func (self *ZeroCopySource) NextInt32() (data int32, eof bool) {
	var val uint32
	val, eof = self.NextUint32()
	return int32(val), eof
}

func (self *ZeroCopySource) NextInt64() (data int64, eof bool) {
	var val uint64
	val, eof = self.NextUint64()
	return int64(val), eof
}

func (self *ZeroCopySource) NextInt16() (data int16, eof bool) {
	var val uint16
	val, eof = self.NextUint16()
	return int16(val), eof
}

func (self *ZeroCopySource) NextVarBytes() (data []byte, size uint64, irregular bool, eof bool) {
	var count uint64
	count, size, irregular, eof = self.NextVarUint()
	size += count

	data, eof = self.NextBytes(count)

	return
}

func (self *ZeroCopySource) NextScalar() (*ristretto255.Scalar, error) {
	b, err := DecodeBytes(self)
	if err != nil {
		return nil, err
	}
	var buf [32]byte
	copy(buf[:], b)
	return ScalarFromBytes(buf), nil
}

func (self *ZeroCopySource) NextElement() (*ristretto255.Element, error) {
	b, err := DecodeBytes(self)
	if err != nil {
		return nil, err
	}
	var buf [32]byte
	copy(buf[:], b)
	return ElementFromBytes(buf), nil
}

func (self *ZeroCopySource) NextString() (data string, size uint64, irregular bool, eof bool) {
	var val []byte
	val, size, irregular, eof = self.NextVarBytes()
	data = string(val)
	return
}

func (self *ZeroCopySource) NextVarUint() (data uint64, size uint64, irregular bool, eof bool) {
	var fb byte
	fb, eof = self.NextByte()
	if eof {
		return
	}

	switch fb {
	case 0xFD:
		val, e := self.NextUint16()
		if e {
			return
		}
		data = uint64(val)
		size = 3
	case 0xFE:
		val, e := self.NextUint32()
		if e {
			return
		}
		data = uint64(val)
		size = 5
	case 0xFF:
		val, e := self.NextUint64()
		if e {
			return
		}
		data = uint64(val)
		size = 9
	default:
		data = uint64(fb)
		size = 1
	}

	irregular = size != getVarUintSize(data)

	return
}

func getVarUintSize(value uint64) uint64 {
	if value < 0xfd {
		return 1
	} else if value <= 0xffff {
		return 3
	} else if value <= 0xFFFFFFFF {
		return 5
	} else {
		return 9
	}
}

// NewReader returns a new ZeroCopySource reading from b.
func NewZeroCopySource(b []byte) *ZeroCopySource { return &ZeroCopySource{b, 0} }

const (
	MAX_UINT64 = math.MaxUint64
)

func SafeSub(x, y uint64) (uint64, bool) {
	return x - y, x < y
}

func SafeAdd(x, y uint64) (uint64, bool) {
	return x + y, y > MAX_UINT64-x
}

func SafeMul(x, y uint64) (uint64, bool) {
	if x == 0 || y == 0 {
		return 0, false
	}
	return x * y, y > MAX_UINT64/x
}

func EncodeBytes(sink *ZeroCopySink, b []byte) (size uint64) {
	return sink.WriteVarBytes(b[:])
}

func DecodeBytes(source *ZeroCopySource) ([]byte, error) {
	from, _, irregular, eof := source.NextVarBytes()
	if eof {
		return nil, io.ErrUnexpectedEOF
	}
	if irregular {
		return nil, ErrIrregularData
	}

	return from, nil
}
