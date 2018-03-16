package blockchain_test

import (
	"testing"

	blockchain "github.com/dradtke/go-blockchain"
)

func TestBlocks(t *testing.T) {
	genesis := blockchain.NewBlock(nil, []byte("hello blockchain"))
	t.Logf("block 1 hash: %s", genesis.HashString())

	block2 := blockchain.NewBlock(genesis.Hash(), []byte("hello again blockchain"))
	t.Logf("block 2 hash: %s", block2.HashString())

	block3 := blockchain.NewBlock(block2.Hash(), []byte("hello once again blockchain"))
	t.Logf("block 2 hash: %s", block3.HashString())
}

func TestBlockchain(t *testing.T) {
	const difficulty = 1
	chain := blockchain.New(difficulty)
	chain.Add([]byte("hello blockchain"))
	chain.Add([]byte("hello again blockchain"))
	chain.Add([]byte("hello once again blockchain"))

	if chain.Len() != 3 {
		t.Error("unexpected blockchain length")
	}
	if chain.Valid() {
		t.Error("blockchain was valid with no mining work done")
	}
}

func TestEmptyBlockchain(t *testing.T) {
	const difficulty = 1
	chain := blockchain.New(difficulty)

	if !chain.Valid() {
		t.Error("an empty blockchain must be valid")
	}
}

func TestMining(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	const difficulty = 6
	chain := blockchain.New(difficulty)
	t.Log(chain.Add([]byte("hello blockchain")).Mine(difficulty))
	t.Log(chain.Add([]byte("hello again blockchain")).Mine(difficulty))
	t.Log(chain.Add([]byte("hello once again blockchain")).Mine(difficulty))

	if chain.Len() != 3 {
		t.Error("unexpected blockchain length")
	}
	if !chain.Valid() {
		t.Error("blockchain is not valid")
	}
}
