// Package blockchain implements a simple blockchain.
//
// The design is inspired by this post on how to build one in Java:
// https://medium.com/programmers-blockchain/create-simple-blockchain-java-tutorial-from-scratch-6eeed3cb03fa
package blockchain

import (
	"bytes"
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"time"
)

// Block represents a single piece of data in the blockchain.
type Block struct {
	prevHash  []byte
	timestamp time.Time
	nonce     uint32
	data      []byte
}

// NewBlock constructs a new block from the previous block's hash and an
// arbitrary chunk of data.
func NewBlock(prevHash, data []byte) *Block {
	const initialNonce = 0
	timestamp := time.Now()
	return &Block{
		prevHash:  prevHash,
		timestamp: timestamp,
		nonce:     initialNonce,
		data:      data,
	}
}

// Hash calculates the block's hash. It uses the previous block's hash along
// with this block's timestamp, nonce, and data.
func (b Block) Hash() []byte {
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, b.nonce)

	hasher := sha256.New()
	hasher.Write(b.prevHash)
	hasher.Write(mustBinary(b.timestamp.MarshalBinary()))
	hasher.Write(v)
	hasher.Write(b.data)
	return hasher.Sum(nil)
}

// HashString returns the hex-encoded result of Hash().
func (b Block) HashString() string {
	return hex.EncodeToString(b.Hash())
}

// Timestamp returns the block's timestamp.
func (b Block) Timestamp() time.Time {
	return b.timestamp
}

// Data returns the block's data.
func (b Block) Data() []byte {
	return b.data
}

// Mine attempts to make this block valid by searching for a nonce value that
// will qualify as proof-of-work. Once it succeeds, it returns the resulting
// hex-encoded hash.
func (b *Block) Mine(difficulty int) string {
	target := strings.Repeat("0", difficulty)
	for !strings.HasPrefix(b.HashString(), target) {
		b.nonce++
	}
	return b.HashString()
}

// Blockchain represents the blockchain.
type Blockchain struct {
	l           *list.List
	difficulty  int
	proofPrefix string
}

// New constructs a new Blockchain with the provided mining difficulty.
func New(difficulty int) Blockchain {
	return Blockchain{
		l:           list.New(),
		difficulty:  difficulty,
		proofPrefix: strings.Repeat("0", difficulty),
	}
}

// Add adds a new block to the chain, returning a reference to it so that
// it can be mined.
func (c Blockchain) Add(data []byte) *Block {
	var prevHash []byte
	if c.l.Len() > 0 {
		prevHash = c.l.Back().Value.(*Block).Hash()
	}
	block := NewBlock(prevHash, data)
	c.l.PushBack(block)
	return block
}

// Len returns the length of the blockchain.
func (c Blockchain) Len() int {
	return c.l.Len()
}

// WorkProven returns true if the provided hex-encoded hash counts as valid
// proof-of-work.
func (c Blockchain) WorkProven(hash string) bool {
	return strings.HasPrefix(hash, c.proofPrefix)
}

// Valid checks if this blockchain is valid. For a blockchain to be valid,
// each block must have valid proof-of-work, and each previous hash reference
// must match that of the previous block.
func (c Blockchain) Valid() bool {
	for e := c.l.Front(); e != nil; e = e.Next() {
		currBlock := e.Value.(*Block)
		if !c.WorkProven(currBlock.HashString()) {
			return false
		}

		if prev := e.Prev(); prev != nil {
			prevBlock := prev.Value.(*Block)

			if !bytes.Equal(prevBlock.Hash(), currBlock.prevHash) {
				return false
			}
		}
	}

	return true
}

// Identity represents a user of the blockchain. It's analogous to bitcoin's
// wallet in that it is used to sign messages.
type Identity struct {
	signer *ecdsa.PrivateKey
}

// NewIdentity constructs a new identity. In doing so it generates a new
// private/public key pair.
func NewIdentity() (Identity, error) {
	// No idea which elliptic curve is best here.
	privateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		return Identity{}, errors.New("blockchain.NewIdentity: " + err.Error())
	}

	return Identity{
		signer: privateKey,
	}, nil
}

// PublicKey returns the public key associated with this identity.
func (i Identity) PublicKey() *ecdsa.PublicKey {
	return &i.signer.PublicKey
}

// Transaction represents a (potentially) signed message on the blockchain.
type Transaction struct {
	sender, receiver *ecdsa.PublicKey
	// random is a random sequence of bytes intended to reduce the chances of hash collisions
	data, random []byte
	sig1, sig2   *big.Int
}

// NewTransaction constructs a new message from one identity to another.
func NewTransaction(from, to *ecdsa.PublicKey, data []byte) Transaction {
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		panic(err)
	}
	return Transaction{
		sender:   from,
		receiver: to,
		data:     data,
		random:   random,
	}
}

// Hash returns this transaction's hash, which serves as an identifier.
func (t Transaction) Hash() []byte {
	hasher := sha256.New()
	hasher.Write(mustBinary(x509.MarshalPKIXPublicKey(t.sender)))
	hasher.Write(mustBinary(x509.MarshalPKIXPublicKey(t.receiver)))
	hasher.Write(t.data)
	hasher.Write(t.random)
	return hasher.Sum(nil)
}

// Data returns the underlying data of this transaction.
func (t Transaction) Data() []byte {
	return t.data
}

// Sender returns a hex-encoded version of the sender's public key.
func (t Transaction) Sender() string {
	return hex.EncodeToString(mustBinary(x509.MarshalPKIXPublicKey(t.sender)))
}

// Receiver returns a hex-encoded version of the receiver's public key.
func (t Transaction) Receiver() string {
	return hex.EncodeToString(mustBinary(x509.MarshalPKIXPublicKey(t.receiver)))
}

// Sign signs the transaction using the given identity. It must be equal to the
// sender of the message, but for security reasons we don't want to save the
// private key within the transaction itself.
func (t *Transaction) Sign(identity Identity) error {
	if !bytes.Equal(mustBinary(x509.MarshalPKIXPublicKey(identity.PublicKey())), mustBinary(x509.MarshalPKIXPublicKey(t.sender))) {
		return errors.New("can't sign transaction unless you're the sender")
	}

	r, s, err := ecdsa.Sign(rand.Reader, identity.signer, t.Hash())
	if err != nil {
		return errors.New("blockchain.Transaction.Sign: " + err.Error())
	}
	t.sig1, t.sig2 = r, s
	return nil
}

// Verify returns true if the transaction was signed and could be verified,
// otherwise false.
func (t *Transaction) Verify() bool {
	if t.sig1 == nil || t.sig2 == nil {
		return false
	}
	return ecdsa.Verify(t.sender, t.Hash(), t.sig1, t.sig2)
}

func mustBinary(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}
