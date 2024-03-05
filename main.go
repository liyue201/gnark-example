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

type TestCircuit struct {
	A frontend.Variable `gnark:",public"`
	B frontend.Variable `gnark:",public"`
	C frontend.Variable
}

func (circuit *TestCircuit) Define(api frontend.API) error {
	c := api.Add(circuit.A, circuit.B)
	api.AssertIsEqual(circuit.C, c)
	return nil
}

func prove() {
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &TestCircuit{}, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		fmt.Printf("Compile error: %v\n", err)
		return
	}
	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		fmt.Printf("Setup error: %v\n", err)
		return
	}

	f, err := os.Create("verifier.sol")
	if err != nil {
		fmt.Printf("Create file error: %v\n", err)
		return
	}
	err = vk.ExportSolidity(f)
	if err != nil {
		fmt.Printf("ExportSolidity error: %v\n", err)
		return
	}
	assignment := TestCircuit{
		A: 1,
		B: 2,
		C: 3,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("NewWitness error: %v\n", err)
		return
	}
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		fmt.Printf("NewWitness error: %v\n", err)
		return
	}
	buf := bytes.Buffer{}
	_, err = proof.WriteRawTo(&buf)
	if err != nil {
		fmt.Printf("NewWitness error: %v\n", err)
		return
	}

	proofInt := writeProof(buf.Bytes())
	saveJson("proof.json", proofInt)

	input := make([]*big.Int, 2)
	input[0] = big.NewInt(1)
	input[1] = big.NewInt(2)
	saveJson("input.json", input)

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
	prove()
}
