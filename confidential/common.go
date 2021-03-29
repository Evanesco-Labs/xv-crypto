package confidential

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/Evanesco-Labs/ristretto255"
	"io"
)

type InnerProductProof struct {
	iteration int32
	Ls, Rs    []*ristretto255.Element
	a, b      *ristretto255.Scalar
}

func (self *InnerProductProof) Serialize() []byte {
	buf := new(bytes.Buffer)
	writeProof(buf, self)
	return buf.Bytes()
}

func (self *InnerProductProof) Deserialize(b []byte) error {
	buf := new(bytes.Buffer)
	buf.Write(b)
	return readProof(buf, self)
}

func ScalarToBytes(i *ristretto255.Scalar) [32]byte {
	b := i.Encode([]byte{})
	var result [32]byte
	copy(result[:], b)
	return result
}

func ScalarFromBytes(b [32]byte) *ristretto255.Scalar {
	var s ristretto255.Scalar
	err := s.Decode(b[:])
	if err != nil {
		panic(err)
	}
	return &s
}

func ElementToBytes(element *ristretto255.Element) [32]byte {
	var buf [32]byte
	b := element.Encode([]byte{})
	copy(buf[:], b)
	return buf
}

func ElementFromBytes(buf [32]byte) *ristretto255.Element {
	var element ristretto255.Element
	element.Decode(buf[:])
	return &element
}

// iteration||a||b||Ls||Rs
func writeProof(w io.Writer, proof *InnerProductProof) error {
	err := writeElements(w, proof.iteration, ScalarToBytes(proof.a), ScalarToBytes(proof.b))
	if err != nil {
		return err
	}
	for _, l := range proof.Ls {
		err = writeElement(w, ElementToBytes(l))
	}
	if err != nil {
		return err
	}
	for _, r := range proof.Rs {
		err = writeElement(w, ElementToBytes(r))
	}
	if err != nil {
		return err
	}
	return nil

}

func readProof(r io.Reader, proof *InnerProductProof) error {
	var bufa, bufb [32]byte
	err := readElements(r, &proof.iteration, &bufa, &bufb)
	if err != nil {
		return err
	}
	proof.a = ScalarFromBytes(bufa)
	proof.b = ScalarFromBytes(bufb)

	for i := 0; i < int(proof.iteration); i++ {
		var bufPoint [32]byte
		err = readElement(r, &bufPoint)
		if err != nil {
			return err
		}
		l := ElementFromBytes(bufPoint)
		proof.Ls = append(proof.Ls, l)
	}

	for i := 0; i < int(proof.iteration); i++ {
		var bufPoint [32]byte
		err = readElement(r, &bufPoint)
		if err != nil {
			return err
		}
		r := ElementFromBytes(bufPoint)
		proof.Rs = append(proof.Rs, r)
	}
	return nil
}

func writeElements(w io.Writer, elements ...interface{}) error {
	for _, element := range elements {
		err := writeElement(w, element)
		if err != nil {
			return err
		}
	}
	return nil
}
func writeElement(w io.Writer, element interface{}) error {
	var scratch [8]byte
	// Attempt to write the element based on the concrete type via fast
	// type assertions first.
	switch e := element.(type) {
	case int32:
		b := scratch[0:4]
		binary.LittleEndian.PutUint32(b, uint32(e))
		_, err := w.Write(b)
		if err != nil {
			return err
		}
		return nil

	case [32]byte:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}
		return nil

	// IP address.
	case [33]byte:
		_, err := w.Write(e[:])
		if err != nil {
			return err
		}
		return nil
	case *ristretto255.Scalar:
		b := ScalarToBytes(e)
		_, err := w.Write(b[:])
		if err != nil {
			return err
		}
		return nil
	case *ristretto255.Element:
		b := ElementToBytes(e)
		_, err := w.Write(b[:])
		if err != nil {
			return err
		}
		return nil
	case InnerProductProof:
		b := e.Serialize()
		_, err := w.Write(b[:])
		if err != nil {
			return err
		}
		return nil
	}

	return errors.New("invalid element")
}
func readElements(r io.Reader, elements ...interface{}) error {
	for _, element := range elements {
		err := readElement(r, element)
		if err != nil {
			return err
		}
	}
	return nil
}

// readElement reads the next sequence of bytes from r using little endian
// depending on the concrete type of element pointed to.
func readElement(r io.Reader, element interface{}) error {
	var scratch [8]byte
	// Attempt to read the element based on the concrete type via fast
	// type assertions first.
	switch e := element.(type) {
	case *int32:
		b := scratch[0:4]
		_, err := io.ReadFull(r, b)
		if err != nil {
			return err
		}
		*e = int32(binary.LittleEndian.Uint32(b))
		return nil

	case *[32]byte:
		_, err := io.ReadFull(r, e[:])
		if err != nil {
			return err
		}
		return nil

	// IP address.
	case *[33]byte:
		_, err := io.ReadFull(r, e[:])
		if err != nil {
			return err
		}
		return nil
	case *ristretto255.Element:
		var b [32]byte
		_, err := io.ReadFull(r, b[:])
		if err != nil {
			return err
		}
		e = ElementFromBytes(b)
		return nil
	case *ristretto255.Scalar:
		var b [32]byte
		_, err := io.ReadFull(r, b[:])
		if err != nil {
			return err
		}
		e = ScalarFromBytes(b)
		return nil
	case *InnerProductProof:
		b := new(bytes.Buffer)
		_, err := b.ReadFrom(r)
		if err != nil {
			return err
		}
		err = e.Deserialize(b.Bytes())
		if err != nil {
			return err
		}
	case Commitment:

	}

	return errors.New("invalid element")
}

//type SigmaRangeProof struct {
//	Taux       *ristretto255.Scalar  // blinding factors in tHat
//	Mu         *ristretto255.Scalar  // blinding factors in A and S
//	THat       *ristretto255.Scalar  // result of the inner product l(x) · r(x)
//	T1         *ristretto255.Element // commitment to the t_1 coefficient of t(X)
//	T2         *ristretto255.Element // commitment to the t_2 coefficient of t(X)
//	A          *ristretto255.Element // commitment to aL and aR
//	S          *ristretto255.Element // commitment to the blinding vectors sL and sR
//	InnerProof InnerProductProof
//}

//func (proof *SigmaRangeProof) Serialize() ([]byte, error) {
//	buf := new(bytes.Buffer)
//	err := writeElements(buf, proof.Taux, proof.Mu, proof.THat, proof.T1, proof.T2, proof.A, proof.S, proof.InnerProof)
//	if err != nil {
//		return nil, err
//	}
//	return buf.Bytes(), nil
//}

//func (proof *SigmaRangeProof) Deserialize(b []byte) error {
//	buf := new(bytes.Buffer)
//	buf.Write(b)
//	err := readElements(buf, proof.Taux, proof.Mu, proof.THat, proof.T1, proof.T2, proof.A, proof.S, &proof.InnerProof)
//	return err
//}

func (proof *SigmaRangeProof) Serialize() []byte {
	sink := NewZeroCopySink(nil)
	sink.WriteScalar(proof.Taux)
	sink.WriteScalar(proof.Mu)
	sink.WriteScalar(proof.THat)
	sink.WriteElement(proof.T1)
	sink.WriteElement(proof.T2)
	sink.WriteElement(proof.A)
	sink.WriteElement(proof.S)
	text := proof.InnerProof.Serialize()
	EncodeBytes(sink, text)
	return sink.Bytes()
}

func (proof *SigmaRangeProof) Deserialize(b []byte) error {
	var err error
	source := NewZeroCopySource(b)
	proof.Taux, err = source.NextScalar()
	if err != nil {
		return err
	}
	proof.Mu, err = source.NextScalar()
	if err != nil {
		return err
	}
	proof.THat, err = source.NextScalar()
	if err != nil {
		return err
	}
	proof.T1, err = source.NextElement()
	if err != nil {
		return err
	}
	proof.T2, err = source.NextElement()
	if err != nil {
		return err
	}
	proof.A, err = source.NextElement()
	if err != nil {
		return err
	}
	proof.S, err = source.NextElement()
	if err != nil {
		return err
	}
	text, err := DecodeBytes(source)
	if err != nil {
		return err
	}
	err = proof.InnerProof.Deserialize(text)
	if err != nil {
		return err
	}
	return nil
}

//type TransferProof struct {
//	sigmaRangeProof         *SigmaRangeProof
//	ay, ad, ab, ayPrime, at *ristretto255.Element
//	ssk, sr, sb, stau       *ristretto255.Scalar
//	cComm, cPrimeComm       Commitment
//}

func (proof *TransferProof) Serialize() []byte {
	sink := NewZeroCopySink(nil)
	sink.WriteElement(proof.ay)
	sink.WriteElement(proof.ad)
	sink.WriteElement(proof.ab)
	sink.WriteElement(proof.ayPrime)
	sink.WriteElement(proof.at)
	sink.WriteScalar(proof.ssk)
	sink.WriteScalar(proof.sr)
	sink.WriteScalar(proof.sb)
	sink.WriteScalar(proof.stau)
	cComm := proof.CComm.Encode()
	EncodeBytes(sink, cComm)
	cPrimeComm := proof.CPrimeComm.Encode()
	EncodeBytes(sink, cPrimeComm)
	text := proof.sigmaRangeProof.Serialize()
	EncodeBytes(sink, text)
	return sink.Bytes()
}

func (proof *TransferProof) Deserialize(b []byte) error {
	var err error
	source := NewZeroCopySource(b)
	proof.ay, err = source.NextElement()
	if err != nil {
		return err
	}
	proof.ad, err = source.NextElement()
	if err != nil {
		return err
	}
	proof.ab, err = source.NextElement()
	if err != nil {
		return err
	}
	proof.ayPrime, err = source.NextElement()
	if err != nil {
		return err
	}
	proof.at, err = source.NextElement()
	if err != nil {
		return err
	}
	proof.ssk, err = source.NextScalar()
	if err != nil {
		return err
	}
	proof.sr, err = source.NextScalar()
	if err != nil {
		return err
	}
	proof.sb, err = source.NextScalar()
	if err != nil {
		return err
	}
	proof.stau, err = source.NextScalar()
	if err != nil {
		return err
	}
	cComm, err := DecodeBytes(source)
	if err != nil {
		return err
	}
	err = proof.CComm.Decode(cComm)
	if err != nil {
		return err
	}
	cCommPrime, err := DecodeBytes(source)
	if err != nil {
		return err
	}
	err = proof.CPrimeComm.Decode(cCommPrime)
	if err != nil {
		return err
	}
	text, err := DecodeBytes(source)
	if err != nil {
		return err
	}
	var sigmagRangeProof SigmaRangeProof
	err = sigmagRangeProof.Deserialize(text)
	if err != nil {
		return err
	}
	proof.sigmaRangeProof = &sigmagRangeProof
	return nil
}

//type BurnProof struct {
//	ay, acr *ristretto255.Element
//	ssk     *ristretto255.Scalar
//	b       *ristretto255.Scalar
//}

func (proof *CommitmentProof) Serialize() []byte {
	sink := NewZeroCopySink(nil)
	sink.WriteElement(proof.ay)
	sink.WriteElement(proof.acr)
	sink.WriteScalar(proof.ssk)
	sink.WriteScalar(proof.B)
	return sink.Bytes()
}

func (proof *CommitmentProof) Deserialize(b []byte) error {
	var err error
	source := NewZeroCopySource(b)
	proof.ay, err = source.NextElement()
	if err != nil {
		return err
	}
	proof.acr, err = source.NextElement()
	if err != nil {
		return err
	}
	proof.ssk, err = source.NextScalar()
	if err != nil {
		return err
	}
	proof.B, err = source.NextScalar()
	if err != nil {
		return err
	}
	return nil
}

//type WithdrawProof struct {
//	rangeProof *RangeProof
//	commWD     Commitment
//	ad, ay, ag *ristretto255.Element
//	ssk, sr    *ristretto255.Scalar
//}
func (proof *WithdrawProof) Serialize() []byte {
	sink := NewZeroCopySink(nil)
	sink.WriteElement(proof.ad)
	sink.WriteElement(proof.ay)
	sink.WriteElement(proof.ag)
	sink.WriteScalar(proof.ssk)
	sink.WriteScalar(proof.sr)
	commWD := proof.CommWD.Encode()
	EncodeBytes(sink, commWD)
	rangeProof := proof.rangeProof.Serialize()
	EncodeBytes(sink, rangeProof)
	return sink.Bytes()
}

func (proof *WithdrawProof) Deserialize(b []byte) error {
	var err error
	source := NewZeroCopySource(b)
	proof.ad, err = source.NextElement()
	if err != nil {
		return err
	}
	proof.ay, err = source.NextElement()
	if err != nil {
		return err
	}
	proof.ag, err = source.NextElement()
	if err != nil {
		return err
	}
	proof.ssk, err = source.NextScalar()
	if err != nil {
		return err
	}
	proof.sr, err = source.NextScalar()
	if err != nil {
		return err
	}
	commWD, err := DecodeBytes(source)
	if err != nil {
		return err
	}
	err = proof.CommWD.Decode(commWD)
	if err != nil {
		return err
	}
	var rangeProof RangeProof
	textRangeProof, err := DecodeBytes(source)
	if err != nil {
		return err
	}
	err = rangeProof.Deserialize(textRangeProof)
	if err != nil {
		return err
	}

	proof.rangeProof = &rangeProof
	return nil
}

//type RangeProof struct {
//	G, H       *ristretto255.Element
//	Taux       *ristretto255.Scalar  // blinding factors in tHat
//	Mu         *ristretto255.Scalar  // blinding factors in A and S
//	THat       *ristretto255.Scalar  // result of the inner product l(x) · r(x)
//	T1         *ristretto255.Element // commitment to the t_1 coefficient of t(X)
//	T2         *ristretto255.Element // commitment to the t_2 coefficient of t(X)
//	A          *ristretto255.Element // commitment to aL and aR
//	S          *ristretto255.Element // commitment to the blinding vectors sL and sR
//	InnerProof InnerProductProof
//}

func (proof *RangeProof) Serialize() []byte {
	sink := NewZeroCopySink(nil)
	sink.WriteElement(proof.G)
	sink.WriteElement(proof.H)
	sink.WriteScalar(proof.Taux)
	sink.WriteScalar(proof.Mu)
	sink.WriteScalar(proof.THat)
	sink.WriteElement(proof.T1)
	sink.WriteElement(proof.T2)
	sink.WriteElement(proof.A)
	sink.WriteElement(proof.S)
	text := proof.InnerProof.Serialize()
	EncodeBytes(sink, text)
	return sink.Bytes()
}

func (proof *RangeProof) Deserialize(b []byte) error {
	var err error
	source := NewZeroCopySource(b)
	proof.G, err = source.NextElement()
	if err != nil {
		return err
	}
	proof.H, err = source.NextElement()
	if err != nil {
		return err
	}
	proof.Taux, err = source.NextScalar()
	if err != nil {
		return err
	}
	proof.Mu, err = source.NextScalar()
	if err != nil {
		return err
	}
	proof.THat, err = source.NextScalar()
	if err != nil {
		return err
	}
	proof.T1, err = source.NextElement()
	if err != nil {
		return err
	}
	proof.T2, err = source.NextElement()
	if err != nil {
		return err
	}
	proof.A, err = source.NextElement()
	if err != nil {
		return err
	}
	proof.S, err = source.NextElement()
	if err != nil {
		return err
	}
	text, err := DecodeBytes(source)
	if err != nil {
		return err
	}
	err = proof.InnerProof.Deserialize(text)
	if err != nil {
		return err
	}
	return nil
}
