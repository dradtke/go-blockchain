package blockchain

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
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

func mustBinary(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}
