package confidential

import (
	"crypto/sha256"
	"github.com/Evanesco-Labs/ristretto255"
)

type Account struct {
	sk          *ristretto255.Scalar
	Pk          *ristretto255.Element
	basePoint   *ristretto255.Element
	xof         XofExpend
	Comm        *Commitment
	PubBalance  uint64
	GList       []*ristretto255.Element
	HList       []*ristretto255.Element
	rangeProver *RangeProver
}

func (acc *Account) Init(seed [32]byte) {
	acc.xof = NewXofExpend(64, seed)
	buf := make([]byte, 64)
	acc.xof.Read(buf)
	randSeed := sha256.Sum256([]byte(rangeProverXofSeed))
	acc.rangeProver, _ = NewRangeProver(32, randSeed)
	acc.basePoint = DeepCopyElement(acc.rangeProver.G)
	acc.sk = new(ristretto255.Scalar).FromUniformBytes(buf)
	acc.Pk = new(ristretto255.Element).ScalarMultWnaf(acc.sk, acc.basePoint)
	zero := new(ristretto255.Scalar).Zero()
	_, comm := acc.Commit(zero)
	acc.Comm = &comm
	acc.PubBalance = uint64(0)
}

func (acc *Account) GetSk() *ristretto255.Scalar {
	return acc.sk
}

func (acc *Account) Deposit(amount uint64) {
	v, _ := InttoScalar(amount)
	_, comm := acc.Commit(v)
	acc.Comm = &comm
	sc.Register(acc.Pk, acc.Comm)
}

func (acc *Account) Commit(v *ristretto255.Scalar) (*ristretto255.Scalar, Commitment) {
	randomBytes := make([]byte, 64)
	acc.xof.Read(randomBytes)
	r := new(ristretto255.Scalar).FromUniformBytes(randomBytes)
	cl := new(ristretto255.Element).Add(new(ristretto255.Element).ScalarMultWnaf(v, acc.basePoint),
		new(ristretto255.Element).ScalarMultWnaf(r, acc.Pk))
	cr := new(ristretto255.Element).ScalarMultWnaf(r, acc.basePoint)
	comm := Commitment{
		Cl: cl,
		Cr: cr,
	}
	return r, comm
}

func (acc *Account) GetCommitmentBalance() *ristretto255.Scalar {
	vEncrypt := new(ristretto255.Element).Add(acc.Comm.Cl,
		new(ristretto255.Element).Negate(new(ristretto255.Element).ScalarMultWnaf(acc.sk, acc.Comm.Cr)))
	return GuessValue(vEncrypt, acc.basePoint, Upper)
}

func (acc *Account) GenDepositProof(v uint64, comm Commitment) CommitmentProof {
	ksk := acc.RandScalar()
	Ay := new(ristretto255.Element).ScalarMultWnaf(ksk, acc.basePoint)
	Acr := new(ristretto255.Element).ScalarMultWnaf(ksk, comm.Cr)
	AyBytes := Ay.Encode(nil)
	AcrBytes := Acr.Encode(nil)

	seed := sha256.Sum256(append(AyBytes, AcrBytes...))
	transcript := NewXofExpend(64, seed)
	buf := make([]byte, 64)
	transcript.Read(buf)
	c := new(ristretto255.Scalar).FromUniformBytes(buf)

	ssk := new(ristretto255.Scalar).Add(ksk, new(ristretto255.Scalar).Multiply(c, acc.sk))

	vScalar, _ := InttoScalar(v)
	return CommitmentProof{
		ay:  Ay,
		acr: Acr,
		ssk: ssk,
		B:   vScalar,
	}
}

func (acc *Account) GenBurnProof() CommitmentProof {
	ksk := acc.RandScalar()
	Ay := new(ristretto255.Element).ScalarMultWnaf(ksk, acc.basePoint)
	Acr := new(ristretto255.Element).ScalarMultWnaf(ksk, acc.Comm.Cr)
	AyBytes := Ay.Encode(nil)
	AcrBytes := Acr.Encode(nil)

	seed := sha256.Sum256(append(AyBytes, AcrBytes...))
	transcript := NewXofExpend(64, seed)
	buf := make([]byte, 64)
	transcript.Read(buf)
	c := new(ristretto255.Scalar).FromUniformBytes(buf)

	ssk := new(ristretto255.Scalar).Add(ksk, new(ristretto255.Scalar).Multiply(c, acc.sk))

	return CommitmentProof{
		ay:  Ay,
		acr: Acr,
		ssk: ssk,
		B:   acc.GetCommitmentBalance(),
	}
}

func (acc *Account) RandScalar() *ristretto255.Scalar {
	buf := make([]byte, 64)
	acc.xof.Read(buf)
	return new(ristretto255.Scalar).FromUniformBytes(buf)
}

func (acc *Account) GenTransferProof(trans [64]byte, amount uint64, yPrime *ristretto255.Element) (*TransferProof, error) {
	b, err := InttoScalar(amount)
	if err != nil {
		return nil, err
	}
	r, cComm := acc.Commit(b)
	c := cComm.Cl
	d := cComm.Cr
	cPrime := new(ristretto255.Element).Add(new(ristretto255.Element).ScalarMultWnaf(b, acc.basePoint),
		new(ristretto255.Element).ScalarMultWnaf(r, yPrime))
	cPrimeCommiment := Commitment{
		Cl: cPrime,
		Cr: cComm.Cr,
	}
	clNew := new(ristretto255.Element).Add(acc.Comm.Cl, new(ristretto255.Element).Negate(c))
	crNew := new(ristretto255.Element).Add(acc.Comm.Cr, new(ristretto255.Element).Negate(d))
	accBalance := ScalartoInt(acc.GetCommitmentBalance())
	bPrime, err := InttoScalar(accBalance - amount)
	if err != nil {
		return nil, err
	}
	pedComm := ElgamalCommitment{
		g:     acc.basePoint,
		h:     acc.Pk,
		v:     b,
		gamma: r,
		comm:  c,
	}
	pedCommPrime := ElgamalCommitment{
		g:     acc.basePoint,
		h:     crNew,
		v:     bPrime,
		gamma: acc.sk,
		comm:  clNew,
	}

	sigRangeProof, z, trans, err := acc.rangeProver.GenSigmaRangeProof(trans, amount, accBalance-amount, pedComm, pedCommPrime)
	if err != nil {
		return nil, err
	}

	//gen sigmaproof
	ksk := acc.RandScalar()
	kr := acc.RandScalar()
	kb := acc.RandScalar()
	ktau := acc.RandScalar()

	ay := new(ristretto255.Element).ScalarMultWnaf(ksk, acc.basePoint)
	ad := new(ristretto255.Element).ScalarMultWnaf(kr, acc.basePoint)
	zz := new(ristretto255.Scalar).Multiply(z, z)
	zzz := new(ristretto255.Scalar).Multiply(zz, z)
	kskzz := new(ristretto255.Scalar).Multiply(ksk, zz)
	kskzzz := new(ristretto255.Scalar).Multiply(ksk, zzz)
	//ab := SumElements(new(ristretto255.Element).ScalarMultWnaf(kb, acc.basePoint),
	//	new(ristretto255.Element).ScalarMultWnaf(new(ristretto255.Scalar).Negate(kskzz), d),
	//	new(ristretto255.Element).ScalarMultWnaf(new(ristretto255.Scalar).Negate(kskzzz), crNew))
	ab := SumElements(new(ristretto255.Element).ScalarMultWnaf(kb, acc.basePoint),
		new(ristretto255.Element).ScalarMultWnaf(kskzz, d),
		new(ristretto255.Element).ScalarMultWnaf(kskzzz, crNew))
	ayPrime := new(ristretto255.Element).ScalarMultWnaf(kr,
		new(ristretto255.Element).Add(acc.Pk, new(ristretto255.Element).Negate(yPrime)))
	at := new(ristretto255.Element).Add(
		new(ristretto255.Element).ScalarMultWnaf(new(ristretto255.Scalar).Negate(kb), acc.basePoint),
		new(ristretto255.Element).ScalarMultWnaf(ktau, acc.rangeProver.H))
	trans, challenge := UpdateTranscript(trans, ay, ad, ab, ayPrime, at)
	ssk := new(ristretto255.Scalar).Add(ksk, Mul(challenge, acc.sk))
	sr := new(ristretto255.Scalar).Add(kr, Mul(challenge, r))
	sb := new(ristretto255.Scalar).Add(kb, Mul(challenge, SumScalars(Mul(b, zz), Mul(bPrime, zzz))))
	stau := new(ristretto255.Scalar).Add(ktau, Mul(challenge, sigRangeProof.Taux))
	return &TransferProof{
		sigmaRangeProof: sigRangeProof,
		ay:              ay,
		ad:              ad,
		ab:              ab,
		ayPrime:         ayPrime,
		at:              at,
		ssk:             ssk,
		sr:              sr,
		sb:              sb,
		stau:            stau,
		CComm:           cComm,
		CPrimeComm:      cPrimeCommiment,
	}, nil

}

func (acc *Account) GenWithdrawProof(trans [64]byte, amount uint64) (*WithdrawProof, error) {
	balance := acc.GetCommitmentBalance()
	b, _ := InttoScalar(amount)
	bNew := new(ristretto255.Scalar).Add(balance, new(ristretto255.Scalar).Negate(b))
	r, commWD := acc.Commit(b)
	commNew := new(Commitment).Sub(acc.Comm, &commWD)
	pedComm := ElgamalCommitment{
		g:     acc.basePoint,
		h:     commNew.Cr,
		v:     bNew,
		gamma: acc.sk,
		comm:  commNew.Cl,
	}

	trans, rangeProof, err := acc.rangeProver.GenRangeProof(trans, pedComm)
	if err != nil {
		return nil, err
	}

	kr := acc.RandScalar()
	ksk := acc.RandScalar()

	ay := new(ristretto255.Element).ScalarMultWnaf(kr, acc.Pk)
	ad := new(ristretto255.Element).ScalarMultWnaf(ksk, commWD.Cr)
	ag := new(ristretto255.Element).ScalarMultWnaf(kr, acc.basePoint)

	trans, challenge := UpdateTranscript(trans, ad, ay, ag)

	ssk := SumScalars(ksk, Mul(challenge, acc.sk))
	sr := SumScalars(kr, Mul(challenge, r))

	proof := WithdrawProof{
		rangeProof: rangeProof,
		ad:         ad,
		ay:         ay,
		ag:         ag,
		ssk:        ssk,
		sr:         sr,
		CommWD:     commWD,
	}
	return &proof, nil
}
