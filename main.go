package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"io/ioutil"
	"math/big"
	"os"
)

// a + b = sum
type TestCircuit struct {
	A   frontend.Variable `gnark:",public"`
	B   frontend.Variable
	Sum frontend.Variable
}

func (circuit *TestCircuit) Define(api frontend.API) error {
	s := api.Add(circuit.A, circuit.B)
	api.AssertIsEqual(circuit.Sum, s)
	return nil
}

func setup() (frontend.CompiledConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &TestCircuit{}, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		fmt.Printf("Compile error: %v\n", err)
		return nil, nil, nil, err
	}
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Printf("Setup error: %v\n", err)
		return nil, nil, nil, err
	}

	f, err := os.Create("verifier.sol")
	if err != nil {
		fmt.Printf("Create file error: %v\n", err)
		return nil, nil, nil, err
	}
	err = vk.ExportSolidity(f)
	if err != nil {
		fmt.Printf("ExportSolidity error: %v\n", err)
		return nil, nil, nil, err
	}

	var buffer bytes.Buffer
	vk.WriteRawTo(&buffer)
	os.WriteFile("test.vk", buffer.Bytes(), 0766)

	return r1cs, pk, vk, nil
}

func prove(r1cs frontend.CompiledConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) (groth16.Proof, error) {
	assignment := TestCircuit{
		A:   1,
		B:   2,
		Sum: 3,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254)
	if err != nil {
		fmt.Printf("NewWitness error: %v\n", err)
		return nil, err
	}
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Printf("Prove error: %v\n", err)
		return nil, err
	}
	buf := bytes.Buffer{}
	_, err = proof.WriteRawTo(&buf)
	if err != nil {
		fmt.Printf("WriteRawTo error: %v\n", err)
		return nil, err
	}

	proofInt := writeProof(buf.Bytes())
	saveJson("proof.json", proofInt)

	publicInput := make([]*big.Int, 1)
	publicInput[0] = big.NewInt(1)
	saveJson("input.json", publicInput)

	return proof, nil
}

func verify(vk groth16.VerifyingKey, proof groth16.Proof) {
	assignment := TestCircuit{
		A:   1,
		B:   2,
		Sum: 0,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254)
	if err != nil {
		panic(err)
	}
	publicWitness, _ := witness.Public()

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
	fmt.Printf("verify ok\n")
}

func saveJson(filename string, v interface{}) {
	proofJson, _ := json.MarshalIndent(v, " ", " ")
	ioutil.WriteFile(filename, proofJson, 0644)
}

type Proof struct {
	A [2]*big.Int
	B [2][2]*big.Int
	C [2]*big.Int
}

func writeProof(proofBytes []byte) *Proof {
	const fpSize = 4 * 8

	var proofBlob Proof

	// proof.Ar, proof.Bs, proof.Krs
	proofBlob.A[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	proofBlob.A[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	proofBlob.B[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	proofBlob.B[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	proofBlob.B[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	proofBlob.B[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	proofBlob.C[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	proofBlob.C[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	return &proofBlob
}

func main() {
	r1cs, pk, vk, err := setup()
	if err != nil {
		panic(err)
	}
	proof, err := prove(r1cs, pk, vk)
	if err != nil {
		panic(err)
	}
	verify(vk, proof)
}
