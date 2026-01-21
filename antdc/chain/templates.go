// Copyright © 2025 ANTDChain Contributors
// Licensed under the MIT License (MIT). See LICENSE in the repository root
// for more information.

package chain

import (
    "encoding/hex"
    "errors"
    "fmt"
    "log"
    "math/big"
    "time"

    "github.com/ethereum/go-ethereum/common"
    "github.com/antdaza/antdchain/antdc/block"
    "github.com/antdaza/antdchain/antdc/tx"
)

// BlockTemplate represents a mining template
type BlockTemplate struct {
    Height         uint64                   `json:"height"`
    PrevHash       string                   `json:"previousblockhash"`
    CoinbaseValue  string                   `json:"coinbasevalue"`
    Target         string                   `json:"target"`
    CurTime        uint64                   `json:"curtime"`
    Transactions   []map[string]interface{} `json:"transactions"`
    Version        uint32                   `json:"version"`
    Bits           string                   `json:"bits"`
    Mintime        uint64                   `json:"mintime"`
    Mutable        []string                 `json:"mutable"`
    NonceRange     string                   `json:"noncerange"`
    SigOpLimit     int                      `json:"sigoplimit"`
    SizeLimit      int                      `json:"sizelimit"`
    WeightLimit    int                      `json:"weightlimit"`
    LongPollID     string                   `json:"longpollid"`
    DefaultWitness string                   `json:"default_witness_commitment"`
    Capabilities   []string                 `json:"capabilities"`
    Rules          []string                 `json:"rules"`
    VBAvailable    map[string]int           `json:"vbavailable"`
    VBRequired     int                      `json:"vbrequired"`
    CoinbaseAux    map[string]string        `json:"coinbaseaux"`
}

// GenerateBlockTemplate generates a block template for mining
func (bc *Blockchain) GenerateBlockTemplate(rewardAddr common.Address) (*BlockTemplate, error) {
    if bc == nil {
        return nil, errors.New("blockchain is nil")
    }

    parent := bc.Latest()
    if parent == nil {
        return nil, errors.New("no parent block available")
    }

    // Get confirmed transactions from pool
    confirmedTxs := bc.txPool.GetConfirmedTxs(bc, bc.MinConfirmations())

    // Calculate total fees and build transactions list
    totalFees := big.NewInt(0)
    transactions := make([]map[string]interface{}, 0, len(confirmedTxs))

    for _, t := range confirmedTxs {
        fee := new(big.Int).Mul(new(big.Int).SetUint64(t.Gas), t.GasPrice)
        totalFees.Add(totalFees, fee)

        data, err := t.Serialize()
        if err != nil {
            continue // Skip invalid transactions
        }

        txEntry := map[string]interface{}{
            "data":    hex.EncodeToString(data),
            "txid":    t.Hash().Hex(),
            "hash":    t.Hash().Hex(),
            "depends": []int{},
            "fee":     fee.Int64(),
            "sigops":  1,
            "weight":  len(data) * 4,
        }
        transactions = append(transactions, txEntry)
    }

    // Calculate total reward (200 ANTD block reward + fees)
    blockReward, ok := new(big.Int).SetString("200000000000000000000", 10)
    if !ok {
        // Handle error - maybe use a default value
        blockReward = new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil) // 10^18 = 1 ANTD
        blockReward.Mul(blockReward, big.NewInt(200))                       // 200 ANTD
    }
    coinbaseValue := new(big.Int).Add(blockReward, totalFees)

    // Get current PoW target
    target := bc.pow.GetTarget()
    targetHex := fmt.Sprintf("%064x", target)

    // Convert difficulty to compact format (Bitcoin-style bits)
    compact := diffToCompact(bc.Pow().GetDifficulty())

    now := uint64(time.Now().Unix())
    parentHeight := parent.Header.Number.Uint64()

    return &BlockTemplate{
        Height:         parentHeight + 1,
        PrevHash:       parent.Hash().Hex(),
        CoinbaseValue:  coinbaseValue.String(),
        Target:         targetHex,
        CurTime:        now,
        Transactions:   transactions,
        Version:        536870912, // Bitcoin-compatible version
        Bits:           fmt.Sprintf("%08x", compact),
        Mintime:        now - 7200, // 2 hours ago
        Mutable:        []string{"time", "transactions", "prevblock"},
        NonceRange:     "00000000ffffffff",
        SigOpLimit:     80000,
        SizeLimit:      4000000,
        WeightLimit:    4000000,
        LongPollID:     parent.Hash().Hex() + fmt.Sprintf("%d", len(transactions)),
        DefaultWitness: "",
        Capabilities:   []string{"proposal"},
        Rules:          []string{},
        VBAvailable:    map[string]int{},
        VBRequired:     0,
        CoinbaseAux:    map[string]string{},
    }, nil
}

// CreateMiningBlock creates a mining block
func (bc *Blockchain) CreateMiningBlock(rewardAddr common.Address) (*block.Block, []*tx.Tx, error) {
    return bc.CreatePoSBlock(rewardAddr)
}

// CreatePoSBlock creates a block for Proof-of-Stake consensus
func (bc *Blockchain) CreatePoSBlock(miner common.Address) (*block.Block, []*tx.Tx, error) {
    if miner == (common.Address{}) {
        return nil, nil, errors.New("miner address is empty")
    }

    parent := bc.Latest()
    if parent == nil {
        return nil, nil, errors.New("no parent block")
    }

    // Enforce 12-second block time
    currentTime := uint64(time.Now().Unix())
    if currentTime-parent.Header.Time < 12 {
        wait := 12 - (currentTime - parent.Header.Time)
        log.Printf("[miner] Waiting %d seconds for proper block timing...", wait)
        time.Sleep(time.Duration(wait) * time.Second)
        currentTime = uint64(time.Now().Unix())
    }

    // Check miner eligibility
    if bc.pow != nil {
        eligible, err := bc.pow.VerifyMinerEligibility(
            miner,
            parent.Hash(),
            parent.Header.Number.Uint64()+1,
            currentTime,
        )
        if err != nil || !eligible {
            return nil, nil, fmt.Errorf("miner %s not eligible: %w", miner.Hex(), err)
        }
    }

    // SAFE TRANSACTION INCLUSION
    var includedTxs []*tx.Tx
    if pool := bc.txPool; pool != nil {
        candidates := pool.GetPending()

        // Only include transactions older than 5 seconds → ensures propagation
        propagationDelay := uint64(5)
        cutoff := currentTime - propagationDelay

        includedCount := 0
        skippedRecent := 0

        for _, tx := range candidates {
            if tx == nil {
                continue
            }

            // Skip transactions created too recently
            if tx.Timestamp >= cutoff {
                skippedRecent++
                continue
            }

            // Basic validation
            if valid, err := tx.Verify(); err != nil || !valid {
                continue
            }

            // Check correct nonce
            expectedNonce := bc.State().GetNonce(tx.From)
            if tx.Nonce != expectedNonce {
                continue
            }

            includedTxs = append(includedTxs, tx)
            includedCount++
        }

        // Limit block size
        if len(includedTxs) > 100 {
            includedTxs = includedTxs[:100]
        }

        if skippedRecent > 0 {
            log.Printf("[miner] Skipped %d recent transaction(s) for propagation safety", skippedRecent)
        }
        log.Printf("[blockchain] Including %d well-propagated transaction(s) in block", includedCount)
    }

    // Calculate transaction root
    txRoot := CalcTxRoot(includedTxs)

    // Create block header
    header := &block.Header{
        ParentHash: parent.Hash(),
        Coinbase:   miner,
        Root:       bc.State().Root(),
        TxHash:     txRoot,
        Number:     new(big.Int).Add(parent.Header.Number, big.NewInt(1)),
        GasLimit:   10_000_000,
        Time:       currentTime,
        Difficulty: bc.pow.CalculateExpectedDifficulty(
    parent.Header.Number.Uint64()+1,
    parent.Header.Time,
        currentTime,
      ),
        Extra:      []byte("ANTDChain-PoS"),
    }

    // Create the block
    newBlock, err := block.NewBlock(header, includedTxs, nil)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to create block: %w", err)
    }

    log.Printf("[blockchain] Created PoS block %d with %d transaction(s)",
        header.Number.Uint64(), len(includedTxs))

    return newBlock, includedTxs, nil
}
