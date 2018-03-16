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

func TestSign(t *testing.T) {
	me, you := mustIdentity(blockchain.NewIdentity()), mustIdentity(blockchain.NewIdentity())
	transaction := blockchain.NewTransaction(
		me.PublicKey(),
		you.PublicKey(),
		[]byte("secret message"),
	)

	t.Logf("message from %s to %s: %s", transaction.Sender(), transaction.Receiver(), string(transaction.Data()))

	if transaction.Verify() {
		t.Error("transaction verified before signature")
	}
	if err := transaction.Sign(me); err != nil {
		t.Errorf("failed to sign transaction: %s", err)
	}
	if !transaction.Verify() {
		t.Error("failed to verify transaction")
	}
}

func TestSignByNonSender(t *testing.T) {
	me, you := mustIdentity(blockchain.NewIdentity()), mustIdentity(blockchain.NewIdentity())
	transaction := blockchain.NewTransaction(
		me.PublicKey(),
		you.PublicKey(),
		[]byte("secret message"),
	)

	if err := transaction.Sign(you); err == nil {
		t.Error("shouldn't be able to sign transaction as non-sender")
	} else if err.Error() != "can't sign transaction unless you're the sender" {
		t.Errorf("unexpected error: %s", err)
	}
}

func mustIdentity(identity blockchain.Identity, err error) blockchain.Identity {
	if err != nil {
		panic(err)
	}
	return identity
}
