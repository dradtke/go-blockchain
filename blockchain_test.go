package blockchain_test

import (
	"testing"

	blockchain "github.com/dradtke/go-blockchain"
)

func TestBlockchain(t *testing.T) {
	const difficulty = 2

	chain := blockchain.New(difficulty)
	me, you := mustIdentity(blockchain.NewIdentity()), mustIdentity(blockchain.NewIdentity())

	block := chain.NewBlock()
	if err := block.SendTransaction(me, you.PublicKey(), []byte("why hello there!")); err != nil {
		t.Fatalf("failed to send transaction: %s", err)
	}
	block.Mine()

	block = chain.NewBlock()
	if err := block.SendTransaction(you, me.PublicKey(), []byte("and hello to you too!")); err != nil {
		t.Fatalf("failed to send transaction: %s", err)
	}
	block.Mine()

	if !chain.Valid() {
		t.Error("blockchain is not valid")
	}

	chain.ForEach(func(block *blockchain.Block) {
		t.Log(block)
	})
}

func TestEmptyBlockchain(t *testing.T) {
	const difficulty = 1
	chain := blockchain.New(difficulty)

	if !chain.Valid() {
		t.Error("an empty blockchain must be valid")
	}
}

func mustIdentity(identity blockchain.Identity, err error) blockchain.Identity {
	if err != nil {
		panic(err)
	}
	return identity
}
