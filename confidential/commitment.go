package confidential

import (
	"errors"
	"github.com/calehh/ristretto255"
)

type Commitment struct {
	Cl *ristretto255.Element
	Cr *ristretto255.Element
}

func (comm *Commitment) Encode() []byte {
	clEncoded := ElementToBytes(comm.Cl)
	crEncoded := ElementToBytes(comm.Cr)
	return append(clEncoded[:], crEncoded[:]...)
}

func (comm *Commitment) Decode(b []byte) error {
	if len(b) != 64 {
		return errors.New("Encoded commiment bytes length not 64!")
	}

	var clEncoded [32]byte
	var crEncoded [32]byte

	copy(clEncoded[:], b[:32])
	copy(crEncoded[:], b[32:])

	comm.Cl = ElementFromBytes(clEncoded)
	comm.Cr = ElementFromBytes(crEncoded)
	return nil
}

//a+b
func (comm *Commitment) Add(a, b *Commitment) *Commitment {
	cl := new(ristretto255.Element).Add(a.Cl, b.Cl)
	cr := new(ristretto255.Element).Add(a.Cr, b.Cr)
	result := &Commitment{
		Cl: cl,
		Cr: cr,
	}
	return result
}

//a-b
func (comm *Commitment) Sub(a, b *Commitment) *Commitment {
	cl := new(ristretto255.Element).Add(a.Cl, new(ristretto255.Element).Negate(b.Cl))
	cr := new(ristretto255.Element).Add(a.Cr, new(ristretto255.Element).Negate(b.Cr))
	result := &Commitment{
		Cl: cl,
		Cr: cr,
	}
	return result
}

func GuessValue(vEncrypt *ristretto255.Element, base *ristretto255.Element, upper uint64) *ristretto255.Scalar {
	zero, _ := InttoScalar(uint64(0))
	vGuess := new(ristretto255.Element).ScalarMultWnaf(zero, base)
	for i := uint64(0); i < upper; i++ {
		if vGuess.Equal(vEncrypt) == 1 {
			v, _ := InttoScalar(i)
			return DeepCopyScalar(v)
		}
		vGuess = new(ristretto255.Element).Add(vGuess, base)
	}
	return nil
}

//func GuessValue(vEncrypt *ristretto255.Element, base *ristretto255.Element, upper uint64) *ristretto255.Scalar {
//
//	for i := uint64(0); i < upper; i++ {
//		v, _ := InttoScalar(i)
//		vGuess := new(ristretto255.Element).ScalarMultWnaf(v, base)
//		if vGuess.Equal(vEncrypt) == 1 {
//			return deepCopyScalar(v)
//		}
//		vGuess = new(ristretto255.Element).Add(vGuess, base)
//	}
//	return nil
//}
