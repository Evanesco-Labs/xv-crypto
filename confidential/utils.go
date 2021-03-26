package confidential

import (
	"crypto/sha512"
	"encoding/binary"
	"github.com/calehh/ristretto255"
	"golang.org/x/crypto/blake2s"
	"io"
)

type XofExpend struct {
	Xof  blake2s.XOF
	key  [32]byte
	size uint16
}

func NewXofExpend(size uint16, key [32]byte) XofExpend {
	xofExpend := XofExpend{
		key:  key,
		size: size,
	}
	xofExpend.Expend()
	return xofExpend
}

func (self *XofExpend) Read(p []byte) (int, error) {
	l := len(p)
	if self.Emty() || self.Xof == nil {
		self.Expend()
	}
	updateKey := make([]byte, 32)
	k, _ := self.Xof.Read(updateKey)
	if k != 32 {
		return 0, io.ErrUnexpectedEOF
	}
	copy(self.key[:], updateKey)
	if self.Emty() || self.Xof == nil {
		self.Expend()
	}
	n, _ := self.Xof.Read(p)
	if n != l {
		return 0, io.ErrUnexpectedEOF
	}
	self.Expend()
	return n, nil
}

func (self *XofExpend) Emty() bool {
	check := make([]byte, 0)
	_, err := self.Xof.Read(check)
	return err == io.EOF
}

func (self *XofExpend) Expend() {
	self.Xof, _ = blake2s.NewXOF(self.size+32, self.key[:])
}

func (self *XofExpend) RandomScalar() *ristretto255.Scalar {
	buf := make([]byte,64)
	self.Read(buf)
	return new(ristretto255.Scalar).FromUniformBytes(buf)
}

func (self *XofExpend) RandomElement() *ristretto255.Element {
	buf := make([]byte,64)
	self.Read(buf)
	return new(ristretto255.Element).FromUniformBytes(buf)
}



func InnerProduct(a, b []*ristretto255.Scalar) *ristretto255.Scalar {
	product := new(ristretto255.Scalar).Zero()
	for i := 0; i < len(a); i++ {
		product.Add(product, new(ristretto255.Scalar).Multiply(a[i], b[i]))
	}
	return product
}

func left(s []*ristretto255.Scalar) []*ristretto255.Scalar {
	var r []*ristretto255.Scalar
	for i := range s {
		if i&1 == 0 { // even
			r = append(r, s[i])
		}
	}
	return r
}

func right(s []*ristretto255.Scalar) []*ristretto255.Scalar {
	var r []*ristretto255.Scalar
	for i := range s {
		if i&1 == 1 { // odd
			r = append(r, s[i])
		}
	}
	return r
}

func leftElements(s []*ristretto255.Element) []*ristretto255.Element {
	var r []*ristretto255.Element
	for i := range s {
		if i&1 == 0 { // even
			r = append(r, s[i])
		}
	}
	return r
}

func rightElements(s []*ristretto255.Element) []*ristretto255.Element {
	var r []*ristretto255.Element
	for i := range s {
		if i&1 == 1 { // odd
			r = append(r, s[i])
		}
	}
	return r
}

func HadamardElements(a, b []*ristretto255.Element) []*ristretto255.Element {
	result := make([]*ristretto255.Element, len(a))
	for i := range a {
		result[i] = new(ristretto255.Element).Add(a[i], b[i])
	}
	return result
}

func ScalarMultArray(scalar *ristretto255.Scalar, elements []*ristretto255.Element) (result []*ristretto255.Element) {
	for _, e := range elements {
		result = append(result, new(ristretto255.Element).ScalarMult(scalar, e))
	}
	return result
}

func Square(s *ristretto255.Scalar) *ristretto255.Scalar {
	return new(ristretto255.Scalar).Multiply(s, s)
}

func SumElements(elements ...*ristretto255.Element) *ristretto255.Element {
	if len(elements) < 2 {
		return elements[0]
	}
	result := elements[0]
	for i := 1; i < len(elements); i++ {
		result = new(ristretto255.Element).Add(result, elements[i])
	}
	return result
}

func HadamardScalars(a, b []*ristretto255.Scalar) []*ristretto255.Scalar {
	result := make([]*ristretto255.Scalar, len(a))
	for i := range a {
		result[i] = new(ristretto255.Scalar).Add(a[i], b[i])
	}
	return result
}

func scalarMul(a []*ristretto255.Scalar, b *ristretto255.Scalar) (result []*ristretto255.Scalar) {
	for _, s := range a {
		result = append(result, new(ristretto255.Scalar).Multiply(s, b))
	}
	return result
}

func SumScalars(s ...*ristretto255.Scalar) *ristretto255.Scalar {

	sum := new(ristretto255.Scalar).Zero()
	for _, si := range s {
		sum.Add(sum, si)
	}
	return sum
}

func Mul(scalars ...*ristretto255.Scalar) *ristretto255.Scalar {
	if len(scalars) == 1 {
		return scalars[0]
	}
	result := scalars[0]
	for i := 1; i < len(scalars); i++ {
		result = new(ristretto255.Scalar).Multiply(result, scalars[i])
	}
	return result
}

//little-endian byte string of uint 64
func Uint64ToBytes(n uint64) []byte {
	encode := make([]byte, 32, 32)
	binary.LittleEndian.PutUint64(encode, n)
	return encode
}

func DeepCopyElementList(res []*ristretto255.Element) []*ristretto255.Element {
	dst := make([]*ristretto255.Element, len(res))
	for i := 0; i < len(res); i++ {
		var e ristretto255.Element = *res[i]
		dst[i] = &e
	}
	return dst
}

func DeepCopyElement(res *ristretto255.Element) *ristretto255.Element {
	e := *res
	return &e
}

func DeepCopyScalar(s *ristretto255.Scalar) *ristretto255.Scalar {
	var r ristretto255.Scalar
	r = *s
	return &r
}

func UpdateTranscript(trans [64]byte, pt ...*ristretto255.Element) ([64]byte, *ristretto255.Scalar) {
	h := make([]byte, 64)
	copy(h, trans[:])
	for _, v := range pt {
		vBytes, _ := v.MarshalText()
		h = append(h, vBytes...)
	}
	trans = sha512.Sum512(h)
	return trans, new(ristretto255.Scalar).FromUniformBytes(trans[:])
}

func GenBitVector(n, l uint64) []uint64 {
	bitVector := make([]uint64, l, l)
	temp := uint64(1)
	for i := uint64(0); i < l; i++ {
		if n&temp == uint64(0) {
			bitVector[i] = 0
		} else {
			bitVector[i] = 1
		}
		temp = temp << 1
	}
	return bitVector
}

func InttoScalar(n uint64) (*ristretto255.Scalar, error) {
	encode := Uint64ToBytes(n)
	scalar := new(ristretto255.Scalar)
	if err := scalar.Decode(encode); err != nil {
		return nil, err
	}
	return scalar, nil
}

func ScalartoInt(s *ristretto255.Scalar) uint64 {
	encode := s.Encode([]byte{})
	return binary.LittleEndian.Uint64(encode)
}

func PowersList(y *ristretto255.Scalar, n uint64) []*ristretto255.Scalar {
	k := DeepCopyScalar(y)
	result := make([]*ristretto255.Scalar, n, n)
	scalarOne, _ := InttoScalar(uint64(1))
	result[0] = scalarOne
	for i := uint64(1); i < n; i++ {
		result[i] = k
		k = new(ristretto255.Scalar).Multiply(k, y)
	}
	return result
}

//f(x) = a1*x + a0
func Substitute(a0, a1 []*ristretto255.Scalar, x *ristretto255.Scalar, n uint64) []*ristretto255.Scalar {
	y := make([]*ristretto255.Scalar, n, n)
	for i := uint64(0); i < n; i++ {
		y[i] = SumScalars(a0[i], Mul(a1[i], x))
	}
	return y
}
