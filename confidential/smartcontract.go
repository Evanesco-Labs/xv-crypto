package confidential

import (
	"crypto/sha256"
	"fmt"
	"github.com/Evanesco-Labs/ristretto255"
	"sync"
)

var sc SmartContract

type SmartContract struct {
	Mu               sync.RWMutex
	BasePoint        *ristretto255.Element
	CommitmentMap    map[[32]byte]*Commitment
	PublicBalanceMap map[[32]byte]uint64
	rangeProver      *RangeProver
}

func (sc *SmartContract) Init() {
	randSeed := sha256.Sum256([]byte(rangeProverXofSeed))
	sc.rangeProver, _ = NewRangeProver(32, randSeed)
	sc.CommitmentMap = make(map[[32]byte]*Commitment)
	sc.PublicBalanceMap = make(map[[32]byte]uint64)
	sc.BasePoint = sc.rangeProver.G
}

func (sc *SmartContract) GetCommitment(pk *ristretto255.Element) *Commitment {
	var key [32]byte
	copy(key[:], pk.Encode(nil))
	comm, ok := sc.CommitmentMap[key]
	if !ok {
		fmt.Printf("pk not exist")
		return nil
	}
	return comm
}

func (sc *SmartContract) Register(pk *ristretto255.Element, comm *Commitment) {
	var key [32]byte
	copy(key[:], pk.Encode([]byte{}))
	sc.CommitmentMap[key] = comm
	sc.PublicBalanceMap[key] = uint64(0)
}

func (sc *SmartContract) VeirfyCommitmentProof(pk *ristretto255.Element, comm Commitment, proof CommitmentProof) (result bool) {
	defer func() {
		if e := recover(); e != nil {
			result = false
		}
	}()

	ayBytes := proof.ay.Encode(nil)
	acrBytes := proof.acr.Encode(nil)
	seed := sha256.Sum256(append(ayBytes, acrBytes...))
	transcript := NewXofExpend(64, seed)
	buf := make([]byte, 64)
	transcript.Read(buf)
	c := new(ristretto255.Scalar).FromUniformBytes(buf)

	sskG := new(ristretto255.Element).ScalarMultWnaf(proof.ssk, sc.BasePoint)
	sskCr := new(ristretto255.Element).ScalarMultWnaf(proof.ssk, comm.Cr)

	if tmp := new(ristretto255.Element).Add(proof.ay, new(ristretto255.Element).ScalarMultWnaf(c, pk));
		sskG.Equal(tmp) != 1 {
		return false
	}

	clgb := new(ristretto255.Element).Add(comm.Cl,
		new(ristretto255.Element).Negate(new(ristretto255.Element).ScalarMultWnaf(proof.B, sc.BasePoint)))

	if tmp := new(ristretto255.Element).Add(proof.acr,
		new(ristretto255.Element).ScalarMultWnaf(c, clgb));
		sskCr.Equal(tmp) != 1 {
		return false
	}

	return true
}

func (sc *SmartContract) VerifyBurnProof(pk *ristretto255.Element, proof CommitmentProof) (result bool) {

	defer func() {
		if e := recover(); e != nil {
			result = false
		}
	}()

	comm := sc.GetCommitment(pk)
	if comm == nil {
		return false
	}

	ayBytes := proof.ay.Encode(nil)
	acrBytes := proof.acr.Encode(nil)
	seed := sha256.Sum256(append(ayBytes, acrBytes...))
	transcript := NewXofExpend(64, seed)
	buf := make([]byte, 64)
	transcript.Read(buf)
	c := new(ristretto255.Scalar).FromUniformBytes(buf)

	sskG := new(ristretto255.Element).ScalarMultWnaf(proof.ssk, sc.BasePoint)
	sskCr := new(ristretto255.Element).ScalarMultWnaf(proof.ssk, comm.Cr)

	if tmp := new(ristretto255.Element).Add(proof.ay, new(ristretto255.Element).ScalarMultWnaf(c, pk));
		sskG.Equal(tmp) != 1 {
		return false
	}

	clgb := new(ristretto255.Element).Add(comm.Cl,
		new(ristretto255.Element).Negate(new(ristretto255.Element).ScalarMultWnaf(proof.B, sc.BasePoint)))

	if tmp := new(ristretto255.Element).Add(proof.acr,
		new(ristretto255.Element).ScalarMultWnaf(c, clgb));
		sskCr.Equal(tmp) != 1 {
		return false
	}

	return true
}

func (sc *SmartContract) VerifyTransferProof(trans [64]byte, proof *TransferProof, y, yPrime *ristretto255.Element) (result bool) {

	defer func() {
		if e := recover(); e != nil {
			result = false
		}
	}()

	trans, yRangeProof, z, x, res := sc.rangeProver.VerifySigmaRangeProof(trans, proof.sigmaRangeProof)
	if !res {
		return false
	}

	trans, challenge := UpdateTranscript(trans, proof.ay, proof.ad, proof.ab, proof.ayPrime, proof.at)

	if proof.CComm.Cr.Equal(proof.CPrimeComm.Cr) != 1 {
		return false
	}

	sskG := new(ristretto255.Element).ScalarMultWnaf(proof.ssk, sc.BasePoint)
	if sskG.Equal(new(ristretto255.Element).Add(proof.ay, new(ristretto255.Element).ScalarMultWnaf(challenge, y))) != 1 {
		return false
	}

	srG := new(ristretto255.Element).ScalarMultWnaf(proof.sr, sc.BasePoint)
	if srG.Equal(new(ristretto255.Element).Add(proof.ad, new(ristretto255.Element).ScalarMultWnaf(challenge, proof.CComm.Cr))) != 1 {
		return false
	}

	cOld := sc.GetCommitment(y)
	cNew := new(Commitment).Sub(cOld, &proof.CComm)
	zz := new(ristretto255.Scalar).Multiply(z, z)
	zzz := new(ristretto255.Scalar).Multiply(zz, z)
	tmp := SumElements(new(ristretto255.Element).ScalarMultWnaf(zz, proof.CComm.Cr),
		new(ristretto255.Element).ScalarMultWnaf(zzz, cNew.Cr))
	left := SumElements(new(ristretto255.Element).ScalarMultWnaf(proof.sb, sc.BasePoint),
		new(ristretto255.Element).ScalarMultWnaf(proof.ssk, tmp))
	tmp = SumElements(new(ristretto255.Element).ScalarMultWnaf(zz, proof.CComm.Cl),
		new(ristretto255.Element).ScalarMultWnaf(zzz, cNew.Cl))
	right := new(ristretto255.Element).Add(proof.ab, new(ristretto255.Element).ScalarMultWnaf(challenge, tmp))
	if left.Equal(right) != 1 {
		return false
	}

	tmp = new(ristretto255.Element).Add(y, new(ristretto255.Element).Negate(yPrime))
	left = new(ristretto255.Element).ScalarMultWnaf(proof.sr, tmp)
	tmp = new(ristretto255.Element).Add(proof.CComm.Cl, new(ristretto255.Element).Negate(proof.CPrimeComm.Cl))
	right = new(ristretto255.Element).Add(proof.ayPrime, new(ristretto255.Element).ScalarMultWnaf(challenge, tmp))
	if left.Equal(right) != 1 {
		return false
	}

	delta := sc.rangeProver.GetAggDelta(yRangeProof, z, uint64(2))
	t := new(ristretto255.Scalar).Add(proof.sigmaRangeProof.THat, new(ristretto255.Scalar).Negate(delta))
	tmpScalar := SumScalars(Mul(t, challenge), new(ristretto255.Scalar).Negate(proof.sb))
	left = SumElements(new(ristretto255.Element).ScalarMultWnaf(tmpScalar, sc.BasePoint),
		new(ristretto255.Element).ScalarMultWnaf(proof.stau, sc.rangeProver.H))
	xx := new(ristretto255.Scalar).Multiply(x, x)
	T12 := SumElements(new(ristretto255.Element).ScalarMultWnaf(x, proof.sigmaRangeProof.T1),
		new(ristretto255.Element).ScalarMultWnaf(xx, proof.sigmaRangeProof.T2))
	right = SumElements(proof.at, new(ristretto255.Element).ScalarMultWnaf(challenge, T12))
	if left.Equal(right) != 1 {
		return false
	}

	return true
}

func (sc *SmartContract) VerifyWithDrawProof(trans [64]byte, y *ristretto255.Element, amount uint64, proof *WithdrawProof) (result bool) {

	defer func() {
		if e := recover(); e != nil {
			result = false
		}
	}()

	comm := sc.GetCommitment(y)
	b, _ := InttoScalar(amount)
	commNew := new(Commitment).Sub(comm, &proof.CommWD)
	if commNew.Cr.Equal(proof.rangeProof.H) != 1 {
		return false
	}

	trans, result = sc.rangeProver.VerifyRangeProof(trans, proof.rangeProof, commNew.Cl)
	if !result {
		return false
	}

	trans, challenge := UpdateTranscript(trans, proof.ad, proof.ay, proof.ag)
	cbG := new(ristretto255.Element).ScalarMultWnaf(Mul(challenge, b), sc.BasePoint)

	left := SumElements(cbG, new(ristretto255.Element).ScalarMultWnaf(proof.ssk, proof.CommWD.Cr))
	right := SumElements(proof.ad, new(ristretto255.Element).ScalarMultWnaf(challenge, proof.CommWD.Cl))
	if left.Equal(right) != 1 {
		return false
	}

	left = new(ristretto255.Element).ScalarMultWnaf(proof.sr, sc.BasePoint)
	right = SumElements(proof.ag, new(ristretto255.Element).ScalarMultWnaf(challenge, proof.CommWD.Cr))
	if left.Equal(right) != 1 {
		return false
	}

	left = SumElements(cbG, new(ristretto255.Element).ScalarMultWnaf(proof.sr, y))
	right = SumElements(proof.ay, new(ristretto255.Element).ScalarMultWnaf(challenge, proof.CommWD.Cl))
	if left.Equal(right) != 1 {
		return false
	}

	return true
}

func (sc *SmartContract)VerifyZeroCommitment(){

}
