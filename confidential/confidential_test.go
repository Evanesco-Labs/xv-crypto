package confidential

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"github.com/magiconair/properties/assert"
	"testing"
	"time"
)

func Test_BurnProof(t *testing.T) {
	source := []byte("hello")
	seed := sha256.Sum256(source)
	var acc Account
	acc.Init(seed)
	sc.Init()
	sc.Register(acc.Pk, acc.Comm)
	acc.Deposit(uint64(100))
	t0 := time.Now()
	burnProof := acc.GenBurnProof()
	prooftext := burnProof.Serialize()
	fmt.Println("burnproof len: ", len(prooftext))
	t1 := time.Now()
	var proof CommitmentProof
	err := proof.Deserialize(prooftext)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, sc.VerifyBurnProof(acc.Pk, proof), true)
	t2 := time.Now()
	fmt.Printf("GenBurnProof takes: %v\n", t1.Sub(t0))
	fmt.Printf("VerifyBurnProof takes: %v\n", t2.Sub(t1))
}

func Test_TransferProof(t *testing.T) {
	source := []byte("hello")
	seed := sha256.Sum256(source)
	var acc Account
	acc.Init(seed)
	sc.Init()
	sc.Register(acc.Pk, acc.Comm)
	acc.Deposit(uint64(100))

	sourceRec := []byte("hello")
	seedRec := sha256.Sum256(sourceRec)
	var accRec Account
	accRec.Init(seedRec)
	sc.Register(accRec.Pk, accRec.Comm)
	acc.Deposit(uint64(100))

	trans := sha512.Sum512(source)
	transVerify := sha512.Sum512(source)
	t0 := time.Now()
	transferProof, err := acc.GenTransferProof(trans, uint64(10), accRec.Pk)

	if err != nil {
		t.Error(err)
	}
	prooftext := transferProof.Serialize()
	fmt.Println("transferproof len: ", len(prooftext))
	t1 := time.Now()
	//var proof TransferProof
	//err = proof.Deserialize(prooftext)
	//if err != nil {
	//	t.Error(err)
	//}
	result := sc.VerifyTransferProof(transVerify, transferProof, acc.Pk, accRec.Pk)
	t2 := time.Now()
	assert.Equal(t, result, true)
	fmt.Printf("GenTransferProof takes: %v\n", t1.Sub(t0))
	fmt.Printf("VerifyTransferProof takes: %v\n", t2.Sub(t1))
}

func TestWithDrawProof(t *testing.T) {
	source := []byte("hello")
	seed := sha256.Sum256(source)
	var acc Account
	acc.Init(seed)
	sc.Init()
	sc.Register(acc.Pk, acc.Comm)
	acc.Deposit(uint64(100))

	trans := sha512.Sum512(source)
	transVerify := sha512.Sum512(source)
	t0 := time.Now()
	proof, err := acc.GenWithdrawProof(trans, uint64(60))
	if err != nil {
		t.Error(err)
	}
	textProof := proof.Serialize()
	fmt.Println("withdrawproof len; ", len(textProof))
	t1 := time.Now()
	if err != nil {
		t.Error(err)
	}
	//var withdrawProof WithdrawProof
	//err = withdrawProof.Deserialize(textProof)
	//if err != nil {
	//	t.Error(err)
	//}
	res := sc.VerifyWithDrawProof(transVerify, acc.Pk, uint64(60), proof)
	t2 := time.Now()
	assert.Equal(t, res, true)
	fmt.Printf("GenWithdrawProof takes: %v\n", t1.Sub(t0))
	fmt.Printf("VerifyWithdrawProof takes: %v\n", t2.Sub(t1))
}

func TestGenacc(t *testing.T) {

}
