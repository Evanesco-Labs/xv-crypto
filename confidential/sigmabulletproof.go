package confidential

import (
	"errors"
	"github.com/Evanesco-Labs/ristretto255"
)
const RANGEPROOFCOUNT = 2
var GHXOFSeed = []byte("innerproduct rangeproof")
var rangeProverXofSeed = "rangeprover"

var Upper = uint64(1) << 32

type ElgamalCommitment struct {
	g, h     *ristretto255.Element
	v, gamma *ristretto255.Scalar
	comm     *ristretto255.Element
}

type CommitmentProof struct {
	ay, acr *ristretto255.Element
	ssk     *ristretto255.Scalar
	B       *ristretto255.Scalar
}

type WithdrawProof struct {
	rangeProof *RangeProof
	CommWD     Commitment
	ad, ay, ag *ristretto255.Element
	ssk, sr    *ristretto255.Scalar
}

type TransferProof struct {
	sigmaRangeProof         *SigmaRangeProof
	ay, ad, ab, ayPrime, at *ristretto255.Element
	ssk, sr, sb, stau       *ristretto255.Scalar
	CComm, CPrimeComm       Commitment
}

type SigmaRangeProof struct {
	Taux       *ristretto255.Scalar  // blinding factors in tHat
	Mu         *ristretto255.Scalar  // blinding factors in A and S
	THat       *ristretto255.Scalar  // result of the inner product l(x) · r(x)
	T1         *ristretto255.Element // commitment to the t_1 coefficient of t(X)
	T2         *ristretto255.Element // commitment to the t_2 coefficient of t(X)
	A          *ristretto255.Element // commitment to aL and aR
	S          *ristretto255.Element // commitment to the blinding vectors sL and sR
	InnerProof InnerProductProof
}

type RangeProof struct {
	G, H       *ristretto255.Element
	Taux       *ristretto255.Scalar  // blinding factors in tHat
	Mu         *ristretto255.Scalar  // blinding factors in A and S
	THat       *ristretto255.Scalar  // result of the inner product l(x) · r(x)
	T1         *ristretto255.Element // commitment to the t_1 coefficient of t(X)
	T2         *ristretto255.Element // commitment to the t_2 coefficient of t(X)
	A          *ristretto255.Element // commitment to aL and aR
	S          *ristretto255.Element // commitment to the blinding vectors sL and sR
	InnerProof InnerProductProof
}

type RangeProver struct {
	N            uint64                  //the bit length of the range,proven value less than 2^N-1
	GList, HList []*ristretto255.Element //the generators for normal case prove
	G, H         *ristretto255.Element   //two generators for pedersen commitment
	PowersOfTwo  []*ristretto255.Scalar  //a list of scalars [1,2,4,...,2^(N-1)]
	table        []ristretto255.NafLookupTable8Pro
	tableHalf    []ristretto255.NafLookupTable8Pro
	xof          XofExpend
}

//rangeN and aggCount must be less than 64 also powers of 2.
//randSeed can be encoded from publicKey
func NewRangeProver(rangeN uint64, randSeed [32]byte) (*RangeProver, error) {
	if rangeN > 64 {
		return nil, errors.New("rangeN must be less than 64")
	}

	G, H := generates(int(rangeN)*2+1, GHXOFSeed)
	prover := RangeProver{
		N:     rangeN,
		GList: G[1:],
		HList: H[1:],
		G:     G[0],
		H:     H[0],
	}

	gList := DeepCopyElementList(prover.GList)
	hList := DeepCopyElementList(prover.HList)
	prover.table = ristretto255.GenGHtable(append(gList, hList...))

	gListHalf := DeepCopyElementList(prover.GList[:rangeN])
	hListHalf := DeepCopyElementList(prover.HList[:rangeN])
	prover.tableHalf = ristretto255.GenGHtable(append(gListHalf, hListHalf...))

	scalarTwo, _ := InttoScalar(uint64(2))
	prover.PowersOfTwo = PowersList(scalarTwo, prover.N)

	prover.xof = XofExpend{
		key:  randSeed,
		size: 64,
	}
	prover.xof.Expend()
	return &prover, nil
}

func generates(n int, seed []byte) ([]*ristretto255.Element, []*ristretto255.Element) {
	var G, H []*ristretto255.Element
	xofKey := [32]byte{}
	copy(xofKey[:], seed)
	xof := NewXofExpend(uint16(128), xofKey)
	for i := 0; i < n; i++ {
		seedGH := make([]byte, 128)
		xof.Read(seedGH)
		G = append(G, new(ristretto255.Element).FromUniformBytes(seedGH[:64]))
		H = append(H, new(ristretto255.Element).FromUniformBytes(seedGH[64:]))
	}
	return G, H
}

func (self *RangeProver) RandScalar() *ristretto255.Scalar {
	buf := make([]byte, 64)
	self.xof.Read(buf)
	return new(ristretto255.Scalar).FromUniformBytes(buf)
}

//Generate commitment for value v with blinding value r
func (self *RangeProver) Commit(v, r *ristretto255.Scalar) *ristretto255.Element {
	return SumElements(ristretto255.NewElement().ScalarMult(v, self.G), ristretto255.NewElement().ScalarMult(r, self.H))
}

func (self *RangeProver) GenRandScalar() *ristretto255.Scalar {
	seed := make([]byte, 64)
	self.xof.Read(seed)
	return new(ristretto255.Scalar).FromUniformBytes(seed)
}

//Use the precomputed table to acc multiscalarmult
//Scalars have to be sort by (scalars...,G||H)
func (self *RangeProver) MultiScalarMult_GH(scalars []*ristretto255.Scalar) *ristretto255.Element {
	return new(ristretto255.Element).MultiScalarMult_GH(scalars, self.table)
}

func (self *RangeProver) MultiScalarMult_GH_Half(scalars []*ristretto255.Scalar) *ristretto255.Element {
	return new(ristretto255.Element).MultiScalarMult_GH(scalars, self.tableHalf)
}

func (self *RangeProver) SumMultElements(a, b []*ristretto255.Scalar, G, H []*ristretto255.Element, u *ristretto255.Element) *ristretto255.Element {

	var scalars []*ristretto255.Scalar
	var elements []*ristretto255.Element
	product := InnerProduct(a, b)

	scalars = append(scalars, a...)
	scalars = append(scalars, b...)
	scalars = append(scalars, product)

	elements = append(elements, G...)
	elements = append(elements, H...)
	elements = append(elements, u)
	result := new(ristretto255.Element).VarTimeMultiScalarMult(scalars, elements)
	return result
}

func (rangeProver *RangeProver) GenSigmaRangeProof(trans [64]byte, b, bPrime uint64, comm, commPrime ElgamalCommitment) (*SigmaRangeProof, *ristretto255.Scalar, [64]byte, error) {
	scalarOne, _ := InttoScalar(uint64(1))
	v, err := InttoScalar(b)
	if err != nil {
		return nil, nil, trans, err
	}
	vPrime, err := InttoScalar(bPrime)
	if err != nil {
		return nil, nil, trans, err
	}
	if v.Equal(comm.v) != 1 {
		return nil, nil, trans, errors.New("v not right")
	}
	if vPrime.Equal(commPrime.v) != 1 {
		return nil, nil, trans, errors.New("vPrime not right")
	}

	bitLen := 2 * rangeProver.N

	G := DeepCopyElementList(rangeProver.GList)
	H := DeepCopyElementList(rangeProver.HList)

	bitvector := GenBitVector(b, rangeProver.N)
	bitvectorPrime := GenBitVector(bPrime, rangeProver.N)

	conBitVector := append(bitvector, bitvectorPrime...)
	al := make([]*ristretto255.Scalar, bitLen, bitLen)
	ar := make([]*ristretto255.Scalar, bitLen, bitLen)
	for i, _ := range conBitVector {
		al[i], err = InttoScalar(conBitVector[i])
		if err != nil {
			return nil, nil, trans, err
		}
	}
	negateOne := new(ristretto255.Scalar).Negate(scalarOne)
	for i, _ := range al {
		ar[i] = new(ristretto255.Scalar).Add(al[i], negateOne)
	}

	//commitment to al,ar
	alpha := rangeProver.RandScalar()
	aScalarList := append(al, ar...)
	aCommit := rangeProver.MultiScalarMult_GH(aScalarList)
	aCommit = new(ristretto255.Element).Add(aCommit, new(ristretto255.Element).ScalarMultWnaf(alpha, rangeProver.H))

	//commitment to sl sr
	rho := rangeProver.RandScalar()
	sl := make([]*ristretto255.Scalar, bitLen)
	sr := make([]*ristretto255.Scalar, bitLen)
	for i := uint64(0); i < bitLen; i++ {
		sl[i] = rangeProver.RandScalar()
		sr[i] = rangeProver.RandScalar()
	}
	sScalarsList := append(sl, sr...)
	sCommit := rangeProver.MultiScalarMult_GH(sScalarsList)
	sCommit = new(ristretto255.Element).Add(sCommit, new(ristretto255.Element).ScalarMultWnaf(rho, rangeProver.H))

	//update transcript to get challenge y,z
	trans, y := UpdateTranscript(trans, aCommit, sCommit)
	trans, z := UpdateTranscript(trans, aCommit, sCommit)

	//compute t1,t2 for coefficients of t(X)
	//l(x) = l0 + l1*x; r(x) = r0 +r1*x
	powersOfY := PowersList(y, bitLen)
	l0 := make([]*ristretto255.Scalar, bitLen, bitLen)
	l1 := sl
	r0 := make([]*ristretto255.Scalar, bitLen, bitLen)
	r1 := make([]*ristretto255.Scalar, bitLen, bitLen)

	ita := make([]*ristretto255.Scalar, bitLen, bitLen)
	powersOfZ := PowersList(z, uint64(RANGEPROOFCOUNT+2))
	for i := 1; i < RANGEPROOFCOUNT+1; i++ {
		for j := uint64(0); j < rangeProver.N; j++ {
			ita[uint64(i-1)*rangeProver.N+j] = Mul(powersOfZ[i+1], rangeProver.PowersOfTwo[j])
		}
	}

	for i := uint64(0); i < bitLen; i++ {
		l0[i] = new(ristretto255.Scalar).Add(al[i], new(ristretto255.Scalar).Negate(new(ristretto255.Scalar).Multiply(z, scalarOne)))
		r0[i] = Mul(powersOfY[i], new(ristretto255.Scalar).Add(ar[i], new(ristretto255.Scalar).Multiply(z, scalarOne)))
		r0[i] = SumScalars(r0[i], ita[i])
		r1[i] = Mul(powersOfY[i], sr[i])
	}

	//compute t(x)= t0+t1*x+t2*x^2
	t0List := make([]*ristretto255.Scalar, bitLen, bitLen)
	t1List := make([]*ristretto255.Scalar, bitLen, bitLen)
	t2List := make([]*ristretto255.Scalar, bitLen, bitLen)
	for i := uint64(0); i < bitLen; i++ {
		t0List[i] = Mul(l0[i], r0[i])
		t1List[i] = SumScalars(Mul(r1[i], l0[i]), Mul(r0[i], l1[i]))
		t2List[i] = Mul(l1[i], r1[i])
	}

	//t0 := SumScalars(t0List...) //check t0 correctness
	t1 := SumScalars(t1List...)
	t2 := SumScalars(t2List...)

	//commit to t1, t2
	tau1 := rangeProver.RandScalar()
	tau2 := rangeProver.RandScalar()
	t1Commit := rangeProver.Commit(t1, tau1)
	t2Commit := rangeProver.Commit(t2, tau2)

	//update transcript to get challenge x
	trans, x := UpdateTranscript(trans, t1Commit, t2Commit)
	xx := Mul(x, x)
	//l=l(x)
	l := Substitute(l0, l1, x, bitLen)
	//r=r(x)
	r := Substitute(r0, r1, x, bitLen)
	//tHat = <l,r>
	tHat := InnerProduct(l, r)

	//get blinding value for tHat
	taux := SumScalars(Mul(tau2, xx), Mul(tau1, x))

	//get mu
	mu := SumScalars(alpha, Mul(rho, x))

	//build innerproduct proof for <l,r>
	trans, _ = UpdateTranscript(trans, t1Commit, t2Commit)
	u := new(ristretto255.Element).FromUniformBytes(trans[:])

	//build innerproductproof
	hPrime := make([]*ristretto255.Element, bitLen)
	invertY := new(ristretto255.Scalar).Invert(y)
	powersOfInverY := PowersList(invertY, bitLen)
	for i := uint64(0); i < bitLen; i++ {
		hPrime[i] = new(ristretto255.Element).ScalarMult(powersOfInverY[i], H[i])
	}

	innerProof := rangeProver.GenInnerProductProof(trans, bitLen, l, r, u, G, hPrime)

	//compute hHat-delta

	return &SigmaRangeProof{
		Taux:       taux,
		Mu:         mu,
		THat:       tHat,
		T1:         t1Commit,
		T2:         t2Commit,
		A:          aCommit,
		S:          sCommit,
		InnerProof: innerProof,
	}, z, trans, nil

}

func (rangeProver *RangeProver) GenRangeProof(trans [64]byte, comm ElgamalCommitment) (transRet [64]byte, proof *RangeProof, err error) {

	n := rangeProver.N
	G := DeepCopyElementList(rangeProver.GList[:n])
	H := DeepCopyElementList(rangeProver.HList[:n])

	scalarOne, err := InttoScalar(uint64(1))
	if err != nil {
		return trans, nil, err
	}

	vScalar := comm.v
	v := ScalartoInt(vScalar)
	gamma := comm.gamma

	if len(G) != len(H) || len(G) != int(n) {
		return trans, nil, errors.New("prover generator size error")
	}

	//check cm correctness

	//transform v to bit arrays al,ar
	alBitVector := GenBitVector(v, n)
	al := make([]*ristretto255.Scalar, n, n)
	ar := make([]*ristretto255.Scalar, n, n)
	for i, _ := range alBitVector {
		al[i], err = InttoScalar(alBitVector[i])
		if err != nil {
			return trans, nil, err
		}
	}

	negateOne := new(ristretto255.Scalar).Negate(scalarOne)
	for i, _ := range al {
		ar[i] = new(ristretto255.Scalar).Add(al[i], negateOne)
	}

	//commitment to al,ar
	alpha := rangeProver.RandScalar()
	aScalarList := append(al, ar...)
	aCommit := rangeProver.MultiScalarMult_GH_Half(aScalarList)
	aCommit = new(ristretto255.Element).Add(aCommit, new(ristretto255.Element).ScalarMult(alpha, comm.h))

	//commitment to blinding vectors sl, sr
	rho := rangeProver.RandScalar()
	sl := make([]*ristretto255.Scalar, n, n)
	sr := make([]*ristretto255.Scalar, n, n)
	for i := uint64(0); i < n; i++ {
		sl[i] = rangeProver.RandScalar()
		sr[i] = rangeProver.RandScalar()
	}
	sScalarList := append(sl, sr...)
	sCommit := rangeProver.MultiScalarMult_GH_Half(sScalarList)
	sCommit = new(ristretto255.Element).Add(sCommit, new(ristretto255.Element).ScalarMult(rho, comm.h))

	//update transcript to get challenge y,z
	trans, y := UpdateTranscript(trans, aCommit, sCommit)
	trans, z := UpdateTranscript(trans, aCommit, sCommit)

	//compute t1,t2 for coefficients of t(X)
	//l(x) = l0 + l1*x; r(x) = r0 +r1*x
	zz := new(ristretto255.Scalar).Multiply(z, z)
	powersOfY := PowersList(y, uint64(n))
	l0 := make([]*ristretto255.Scalar, n, n)
	l1 := sl
	r0 := make([]*ristretto255.Scalar, n, n)
	r1 := make([]*ristretto255.Scalar, n, n)
	for i := uint64(0); i < n; i++ {
		l0[i] = new(ristretto255.Scalar).Add(al[i], new(ristretto255.Scalar).Negate(new(ristretto255.Scalar).Multiply(z, scalarOne)))
		r0[i] = Mul(powersOfY[i], new(ristretto255.Scalar).Add(ar[i], new(ristretto255.Scalar).Multiply(z, scalarOne)))
		r0[i] = new(ristretto255.Scalar).Add(r0[i], Mul(zz, rangeProver.PowersOfTwo[i]))
		r1[i] = Mul(powersOfY[i], sr[i])
	}

	//compute t(x)= t0+t1*x+t2*x^2
	t0List := make([]*ristretto255.Scalar, n, n)
	t1List := make([]*ristretto255.Scalar, n, n)
	t2List := make([]*ristretto255.Scalar, n, n)
	for i := uint64(0); i < n; i++ {
		t0List[i] = Mul(l0[i], r0[i])
		t1List[i] = SumScalars(Mul(r1[i], l0[i]), Mul(r0[i], l1[i]))
		t2List[i] = Mul(l1[i], r1[i])
	}

	//t0 := SumScalars(t0List...) //check t0 correctness
	t1 := SumScalars(t1List...)
	t2 := SumScalars(t2List...)

	//commit to t1, t2
	tau1 := rangeProver.RandScalar()
	tau2 := rangeProver.RandScalar()
	t1Commit := SumElements(new(ristretto255.Element).ScalarMultWnaf(t1, rangeProver.G),
		new(ristretto255.Element).ScalarMultWnaf(tau1, comm.h))
	t2Commit := SumElements(new(ristretto255.Element).ScalarMultWnaf(t2, rangeProver.G),
		new(ristretto255.Element).ScalarMultWnaf(tau2, comm.h))

	//update transcript to get challenge x
	trans, x := UpdateTranscript(trans, t1Commit, t2Commit)

	xx := Mul(x, x)
	//l=l(x)
	l := Substitute(l0, l1, x, uint64(n))
	//r=r(x)
	r := Substitute(r0, r1, x, uint64(n))
	//tHat = <l,r>
	tHat := InnerProduct(l, r)
	//get blinding value for tHat
	taux := SumScalars(Mul(tau2, xx), Mul(tau1, x), Mul(zz, gamma))
	//get mu
	mu := SumScalars(alpha, Mul(rho, x))

	//build innerproduct proof for <l,r>
	trans, _ = UpdateTranscript(trans, t1Commit, t2Commit)
	u := new(ristretto255.Element).FromUniformBytes(trans[:])

	//build innerproductproof
	hPrime := make([]*ristretto255.Element, n, n)
	invertY := new(ristretto255.Scalar).Invert(y)
	powersOfInverY := PowersList(invertY, uint64(n))
	for i := uint64(0); i < n; i++ {
		hPrime[i] = new(ristretto255.Element).ScalarMult(powersOfInverY[i], H[i])
	}

	innerProof := rangeProver.GenInnerProductProof(trans, n, l, r, u, G, hPrime)

	rangeProof := RangeProof{
		G:          rangeProver.G,
		H:          comm.h,
		Taux:       taux,
		Mu:         mu,
		THat:       tHat,
		T1:         t1Commit,
		T2:         t2Commit,
		A:          aCommit,
		S:          sCommit,
		InnerProof: innerProof,
	}
	return trans, &rangeProof, nil
}

func (self *RangeProver) GenInnerProductProof(trans [64]byte, round uint64, a, b []*ristretto255.Scalar, u *ristretto255.Element,
	G, H []*ristretto255.Element) InnerProductProof {

	P := self.SumMultElements(a, b, G, H, u)

	var Ls, Rs []*ristretto255.Element
	var x *ristretto255.Scalar

	for round != 1 {

		round = round / 2

		Li := self.SumMultElements(left(a), right(b), rightElements(G), leftElements(H), u)
		Ri := self.SumMultElements(right(a), left(b), leftElements(G), rightElements(H), u)

		Ls = append(Ls, Li)
		Rs = append(Rs, Ri)

		trans, x = UpdateTranscript(trans, Li, Ri)
		xInv := new(ristretto255.Scalar).Invert(x)

		G = HadamardElements(
			ScalarMultArray(xInv, leftElements(G)),
			ScalarMultArray(x, rightElements(G)))

		H = HadamardElements(
			ScalarMultArray(x, leftElements(H)),
			ScalarMultArray(xInv, rightElements(H)))

		Lx := new(ristretto255.Element).ScalarMult(Square(x), Li)
		Rx := new(ristretto255.Element).ScalarMult(Square(xInv), Ri)

		P = SumElements(Lx, P, Rx)

		a = HadamardScalars(scalarMul(left(a), x), scalarMul(right(a), xInv))
		b = HadamardScalars(scalarMul(left(b), xInv), scalarMul(right(b), x))

	}

	return InnerProductProof{
		iteration: int32(len(Ls)),
		Ls:        Ls,
		Rs:        Rs,
		a:         a[0],
		b:         b[0],
	}

}

func (rangeProver *RangeProver) VerifySigmaRangeProof(trans [64]byte, proof *SigmaRangeProof) (tran [64]byte, yRes, zRes, xRes *ristretto255.Scalar, result bool) {
	defer func() {
		if err := recover(); err != nil {
			result = false
		}
	}()
	count := uint64(2)
	bitLen := count * rangeProver.N
	G := DeepCopyElementList(rangeProver.GList)
	H := DeepCopyElementList(rangeProver.HList)
	//build random params
	trans, y := UpdateTranscript(trans, proof.A, proof.S)

	trans, z := UpdateTranscript(trans, proof.A, proof.S)

	trans, x := UpdateTranscript(trans, proof.T1, proof.T2)

	trans, _ = UpdateTranscript(trans, proof.T1, proof.T2)
	u := new(ristretto255.Element).FromUniformBytes(trans[:])
	powersOfZ := PowersList(z, count+2)
	negZ := new(ristretto255.Scalar).Negate(z)
	//build h' and gh'table
	hPrime := make([]*ristretto255.Element, bitLen, bitLen)
	invertY := new(ristretto255.Scalar).Invert(y)
	powersOfInverY := PowersList(invertY, bitLen)
	powersOfY := PowersList(y, bitLen)
	for i := uint64(0); i < bitLen; i++ {
		hPrime[i] = new(ristretto255.Element).ScalarMultWnaf(powersOfInverY[i], H[i])
	}

	//compute commitment l(x),r(x)
	scalars := make([]*ristretto255.Scalar, 0)
	for i := uint64(0); i < bitLen; i++ {
		scalars = append(scalars, negZ)
	}
	for j := uint64(0); j < count; j++ {
		for i := uint64(0); i < rangeProver.N; i++ {
			scalar := SumScalars(Mul(z, powersOfY[rangeProver.N*j+i]), Mul(powersOfZ[j+2], rangeProver.PowersOfTwo[i]))
			scalars = append(scalars, scalar)
		}
	}
	//p0 := new(ristretto255.Element).MultiScalarMult_GH(scalars, ghPrimeTable)
	p0 := new(ristretto255.Element).VarTimeMultiScalarMult(scalars, append(G, hPrime...))
	p := SumElements(proof.A, new(ristretto255.Element).ScalarMultWnaf(x, proof.S), p0)
	//pPrime = P*h^(-mu)*u^tHat
	pPrime := SumElements(p, new(ristretto255.Element).ScalarMultWnaf(new(ristretto255.Scalar).Negate(proof.Mu), rangeProver.H))
	pPrime = SumElements(pPrime, new(ristretto255.Element).ScalarMultWnaf(proof.THat, u))
	//check l,r
	//check innerproductproof
	result = rangeProver.VerifyInnerProductProof(trans, bitLen, pPrime, u, G, hPrime, proof.InnerProof)
	return trans, y, z, x, result
}

func (rangeProver *RangeProver) VerifyRangeProof(trans [64]byte, proof *RangeProof, vCommit *ristretto255.Element) (transRet [64]byte, result bool) {
	defer func() {
		if err := recover(); err != nil {
			result = false
		}
	}()
	n := rangeProver.N
	G := DeepCopyElementList(rangeProver.GList[:n])
	H := DeepCopyElementList(rangeProver.HList[:n])

	//build random params
	trans, y := UpdateTranscript(trans, proof.A, proof.S)

	trans, z := UpdateTranscript(trans, proof.A, proof.S)

	trans, x := UpdateTranscript(trans, proof.T1, proof.T2)

	trans, _ = UpdateTranscript(trans, proof.T1, proof.T2)
	u := new(ristretto255.Element).FromUniformBytes(trans[:])

	zz := Mul(z, z)
	xx := Mul(x, x)
	negZ := new(ristretto255.Scalar).Negate(z)

	//build h' and gh'table
	hPrime := make([]*ristretto255.Element, n, n)
	invertY := new(ristretto255.Scalar).Invert(y)
	powersOfInverY := PowersList(invertY, uint64(n))
	powersOfY := PowersList(y, n)
	for i := uint64(0); i < n; i++ {
		hPrime[i] = new(ristretto255.Element).ScalarMultWnaf(powersOfInverY[i], H[i])
	}
	//check tHat
	tHatCommit := SumElements(new(ristretto255.Element).ScalarMultWnaf(proof.THat, rangeProver.G),
		new(ristretto255.Element).ScalarMultWnaf(proof.Taux, proof.H))
	delta := rangeProver.GetDelta(y, z)
	tHatCommitPrime := SumElements(new(ristretto255.Element).ScalarMultWnaf(zz, vCommit),
		new(ristretto255.Element).ScalarMultWnaf(delta, rangeProver.G),
		new(ristretto255.Element).ScalarMultWnaf(x, proof.T1),
		new(ristretto255.Element).ScalarMultWnaf(xx, proof.T2))
	if tHatCommit.Equal(tHatCommitPrime) != 1 {
		return trans, false
	}
	//compute commitment l(x),r(x)
	scalars := make([]*ristretto255.Scalar, 0)
	for i := uint64(0); i < n; i++ {
		scalars = append(scalars, negZ)
	}
	for i := uint64(0); i < n; i++ {
		scalar := SumScalars(Mul(z, powersOfY[i]), Mul(zz, rangeProver.PowersOfTwo[i]))
		scalars = append(scalars, scalar)
	}
	p0 := new(ristretto255.Element).VarTimeMultiScalarMult(scalars, append(G, hPrime...))
	p := SumElements(proof.A, new(ristretto255.Element).ScalarMultWnaf(x, proof.S), p0)
	//pPrime = P*h^(-mu)*u^tHat
	pPrime := SumElements(p, new(ristretto255.Element).ScalarMultWnaf(new(ristretto255.Scalar).Negate(proof.Mu), proof.H))
	pPrime = SumElements(pPrime, new(ristretto255.Element).ScalarMultWnaf(proof.THat, u))
	//check l,r
	//check innerproductproof
	result = rangeProver.VerifyInnerProductProof(trans, n, pPrime, u, G, hPrime, proof.InnerProof)

	return trans, result
}

func (self *RangeProver) VerifyInnerProductProof(trans [64]byte, n uint64, p, u *ristretto255.Element, G, H []*ristretto255.Element, proof InnerProductProof) (result bool) {
	defer func() {
		if err := recover(); err != nil {
			result = false
		}
	}()
	//k rounds of prove iteration
	k := len(proof.Ls)
	if k != len(proof.Rs) {
		return false
	}

	var challenges []*ristretto255.Scalar
	for i := 0; i < k; i++ {
		x := new(ristretto255.Scalar)
		trans, x = UpdateTranscript(trans, proof.Ls[i], proof.Rs[i])
		challenges = append(challenges, x)
	}

	var challengesSquare []*ristretto255.Scalar
	for _, c := range challenges {
		challengesSquare = append(challengesSquare, Square(c))
	}

	s := GetS(challenges, challengesSquare, n, k)

	var as, bsinv []*ristretto255.Scalar
	for i := uint64(0); i < n; i++ {
		as = append(as, new(ristretto255.Scalar).Multiply(proof.a, s[i]))
		bsinv = append(bsinv, new(ristretto255.Scalar).Multiply(proof.b, s[n-i-1]))
	}

	a := []*ristretto255.Scalar{proof.a}
	b := []*ristretto255.Scalar{proof.b}

	right := SumElements(new(ristretto255.Element).VarTimeMultiScalarMult(as, G),
		new(ristretto255.Element).VarTimeMultiScalarMult(bsinv, H),
		new(ristretto255.Element).ScalarMult(InnerProduct(a, b), u))

	left := p
	for i := 0; i < k; i++ {
		left = SumElements(left,
			new(ristretto255.Element).ScalarMult(challengesSquare[i], proof.Ls[i]),
			new(ristretto255.Element).ScalarMult(new(ristretto255.Scalar).Invert(challengesSquare[i]), proof.Rs[i]))
	}

	return left.Equal(right) == 1
}

func GetS(challenges []*ristretto255.Scalar, challengesSquare []*ristretto255.Scalar, n uint64, k int) []*ristretto255.Scalar {
	s := make([]*ristretto255.Scalar, n)
	s[0] = new(ristretto255.Scalar).Invert(Mul(challenges...))

	for i := uint64(2); i < uint64(n+1); i++ {
		s[i-1] = DeepCopyScalar(s[0])
		for j := uint64(0); j < uint64(k); j++ {
			bit := uint64(1) << j
			if bit == (i-1)&bit {
				s[i-1] = new(ristretto255.Scalar).Multiply(s[i-1], challengesSquare[j])
			}
		}
	}

	return s
}

func (self *RangeProver) GetAggDelta(y, z *ristretto255.Scalar, count uint64) *ristretto255.Scalar {
	n := self.N * count
	zz := new(ristretto255.Scalar).Multiply(z, z)
	powersOfZ := PowersList(z, count+3)
	powersOfY := PowersList(y, n)
	sumPowersOf2 := SumScalars(self.PowersOfTwo...)
	negzz := new(ristretto255.Scalar).Negate(zz)
	p2, _ := InttoScalar(uint64(0))
	for i := uint64(1); i < count+1; i++ {
		p2 = SumScalars(p2, Mul(powersOfZ[i+2], sumPowersOf2))
	}
	p1 := Mul(SumScalars(z, negzz), SumScalars(powersOfY...))
	return SumScalars(p1, new(ristretto255.Scalar).Negate(p2))
}

func (self *RangeProver) GetDelta(y, z *ristretto255.Scalar) *ristretto255.Scalar {
	n := self.N
	scalarOne, _ := InttoScalar(uint64(1))
	oneList := make([]*ristretto255.Scalar, n)
	zz := new(ristretto255.Scalar).Multiply(z, z)
	zzz := new(ristretto255.Scalar).Multiply(zz, z)
	for i := uint64(0); i < n; i++ {
		oneList[i] = scalarOne
	}
	powersOfY := PowersList(y, n)
	innery := InnerProduct(oneList, powersOfY)
	inner2 := InnerProduct(oneList, self.PowersOfTwo)
	negzz := new(ristretto255.Scalar).Negate(zz)
	p1 := Mul(SumScalars(z, negzz), innery)
	p2 := Mul(zzz, inner2)
	return SumScalars(p1, new(ristretto255.Scalar).Negate(p2))
}
