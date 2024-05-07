package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"io/ioutil"
	"math/big"
	"os"
)

// a + b = sum
type TestCircuit struct {
	A   frontend.Variable `gnark:",public"`
	B   frontend.Variable `gnark:",public"`
	Sum frontend.Variable
}

func (circuit *TestCircuit) Define(api frontend.API) error {
	s := api.Add(circuit.A, circuit.B)
	api.AssertIsEqual(circuit.Sum, s)
	return nil
}

func setup() (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &TestCircuit{}, frontend.IgnoreUnconstrainedInputs())
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

	return r1cs, pk, vk, nil
}

func prove(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) ([]byte, error) {
	assignment := TestCircuit{
		A:   1,
		B:   2,
		Sum: 3,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
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

	publicInput := make([]*big.Int, 2)
	publicInput[0] = big.NewInt(1)
	publicInput[1] = big.NewInt(2)
	saveJson("input.json", publicInput)

	return buf.Bytes(), nil
}

func verify(vk groth16.VerifyingKey, proofBytes []byte) {
	assignment := TestCircuit{
		A:   1,
		B:   2,
		Sum: 3,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, _ := witness.Public()

	var proof bn254.Proof
	var buf bytes.Buffer
	_, err = buf.Write(proofBytes)
	if err != nil {
		panic(err)
	}
	_, err = proof.ReadFrom(&buf)
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(&proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
	fmt.Printf("verify ok\n")
}

func saveJson(filename string, v interface{}) {
	proofJson, _ := json.MarshalIndent(v, " ", " ")
	ioutil.WriteFile(filename, proofJson, 0644)
}

func writeProof(proofBytes []byte) [8]*big.Int {
	const fpSize = 4 * 8

	var proof [8]*big.Int

	for i := 0; i < 8; i++ {
		proof[i] = new(big.Int).SetBytes(proofBytes[fpSize*i : fpSize*(i+1)])
	}
	return proof
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
