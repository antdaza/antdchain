// Copyright © 2025 ANTDChain Contributors
// Licensed under the MIT License (MIT). See LICENSE in the repository root
// for more information.

package chain

import (
    "context"
    "errors"
    "fmt"
    "log"
    "sort"
    "time"

    "github.com/cockroachdb/pebble"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/rlp"
    "github.com/antdaza/antdchain/antdc/block"
    "github.com/antdaza/antdchain/antdc/chain/db"
    "github.com/antdaza/antdchain/antdc/checkpoints"
)

// AddBlock adds a new block to the blockchain
func (bc *Blockchain) AddBlock(b *block.Block) error {
    if b == nil || b.Header == nil {
        return errors.New("nil block or header")
    }

    blockHash := b.Hash()
    blockHeight := b.Header.Number.Uint64()
    parentHash := b.Header.ParentHash

    log.Printf("[blockchain] AddBlock height=%d hash=%s parent=%s",
        blockHeight, blockHash.Hex()[:12], parentHash.Hex()[:12])

    // ==============================================
    // CHECKPOINT VALIDATION
    // ==============================================
    if bc.checkpointManager != nil {
        // Special handling for genesis block (height 0)
        if blockHeight == 0 {
            // Always validate genesis against checkpoints
            err := bc.checkpointManager.ValidateBlock(blockHeight, blockHash)
            if err != nil {
                log.Printf("[blockchain] ❌ GENESIS BLOCK CHECKPOINT FAILURE: %v", err)
                return fmt.Errorf("genesis block checkpoint validation failed: %w", err)
            }
            log.Printf("[blockchain] ✅ Genesis block checkpoint validated")
        } else {
            // For non-genesis blocks, validate against checkpoint if available
            if cp, exists := bc.checkpointManager.GetCheckpoint(blockHeight); exists {
                err := bc.checkpointManager.ValidateBlock(blockHeight, blockHash)
                if err != nil {
                    log.Printf("[blockchain] ❌ CHECKPOINT FAILURE at height %d: %v", blockHeight, err)
                    return fmt.Errorf("checkpoint validation failed at height %d: %w", blockHeight, err)
                }
                log.Printf("[blockchain] ✅ Block %d validated against checkpoint (verifications: %d)",
                    blockHeight, cp.Verifications)
            } else {
                // No checkpoint for this height, check if we should create one
                if bc.shouldCreateCheckpoint(blockHeight) {
                    log.Printf("[blockchain] 📍 Creating checkpoint at height %d", blockHeight)
                    go bc.createCheckpointFromBlock(b)
                }
            }
        }
    }
    // ==============================================
    // END CHECKPOINT SECTION
    // ==============================================

    // Prevent concurrent processing of the same block
    bc.blockSubmitMu.Lock()
    defer bc.blockSubmitMu.Unlock()

    // Get current tip using atomic load
    currentTip := bc.latest.Load()
    currentHeight := uint64(0)
    if currentTip != nil {
        currentHeight = currentTip.Header.Number.Uint64()
    }
    
    isSyncing := bc.IsSyncing()

    // Reject duplicate by hash
    if bc.HasBlock(blockHash) {
        return fmt.Errorf("duplicate block %s", blockHash.Hex()[:12])
    }

    // Reject if below current height (stale)
    if blockHeight < currentHeight {
        return fmt.Errorf("stale block at height %d (current %d)", blockHeight, currentHeight)
    }

    // Validate and execute the block
    parentBlock := bc.GetBlock(blockHeight - 1)
    if err := bc.validateAndExecuteBlock(b, parentBlock); err != nil {
        return fmt.Errorf("block validation failed: %w", err)
    }

    // Direct extension — fast path
    if blockHeight == currentHeight+1 && parentHash == currentTip.Hash() {
        return bc.handleDirectExtension(b, isSyncing)
    }

    // During sync — accept if parent exists (gap filling)
    if isSyncing {
        if parentBlock == nil {
            return fmt.Errorf("orphan block during sync: parent height %d missing", blockHeight-1)
        }
        return bc.handleDirectExtension(b, true)
    }

    if blockHeight == currentHeight {
        currentBlock := bc.GetBlock(blockHeight)
        if currentBlock.Hash() == blockHash {
            return nil // duplicate
        }

        // Prefer the block with earlier timestamp (deterministic tie-breaker)
        if b.Header.Time < currentBlock.Header.Time {
            log.Printf("[blockchain] Reorg at height %d: switching to earlier timestamp block %s",
                blockHeight, blockHash.Hex()[:12])
            return bc.reorganizeAtHeight(blockHeight, b)
        }

        log.Printf("[blockchain] Fork rejected at height %d: later timestamp", blockHeight)
        return fmt.Errorf("fork block rejected (later timestamp)")
    }

    // Block is ahead — trigger sync
    if blockHeight > currentHeight+1 {
        log.Printf("[blockchain] Block %d is ahead (current %d) — triggering sync", blockHeight, currentHeight)
        go bc.triggerSyncFromBlock(b)
        return fmt.Errorf("block ahead — syncing")
    }

    return fmt.Errorf("unexpected block state")
}

// handleDirectExtension handles direct chain extension
func (bc *Blockchain) handleDirectExtension(b *block.Block, duringSync bool) error {
    bc.stateMu.Lock()
    defer bc.stateMu.Unlock()

    blockHeight := b.Header.Number.Uint64()
    blockHash := b.Hash()

    // Add to database FIRST (this is critical)
    if err := bc.db.WriteBlock(b); err != nil {
        return fmt.Errorf("failed to write block to database: %w", err)
    }

    // Update canonical tip in database
    if err := bc.db.WriteHeadBlockHash(blockHash); err != nil {
        log.Printf("[blockchain] Warning: failed to update head block hash: %v", err)
        // Continue anyway - we can recover from this
    }

    // Update latest block pointer
    bc.latest.Store(b)
    bc.lastCanonicalHeight.Store(blockHeight)

    // Update cache
    bc.cacheMu.Lock()
    bc.blockByNumberCache.Add(blockHeight, b)
    bc.blockByHashCache.Add(blockHash, b)
    bc.cacheMu.Unlock()

    // ==============================================
    // CREATE CHECKPOINT IF NEEDED
    // ==============================================
    if bc.checkpointManager != nil && !duringSync {
        // Only create checkpoints when not syncing
        if bc.shouldCreateCheckpoint(blockHeight) {
            go func() {
                if err := bc.createCheckpointFromBlock(b); err != nil {
                    log.Printf("[blockchain] Failed to create checkpoint at height %d: %v", blockHeight, err)
                } else {
                    log.Printf("[blockchain] ✅ Created checkpoint at height %d", blockHeight)
                }
            }()
        }
    }
    // ==============================================
    // END CHECKPOINT SECTION
    // ==============================================

    if bc.rotatingKingManager != nil {
        go bc.syncRotatingKingForBlock(blockHeight)
    }

    // Check if sync completed
    if duringSync {
        bc.maybeCompleteSync(blockHeight)
    }

    // Note: persistBlockAsync is no longer needed since db.WriteBlock already persists
    // But keep it if it does additional processing
    go bc.persistBlockAsync(b)

    // Cleanup mined txs
    if len(b.Txs) > 0 && bc.txPool != nil {
        bc.txPool.CleanupMinedTransactions(b.Txs)
    }

    log.Printf("[blockchain] Accepted block → height=%d hash=%s txs=%d",
        blockHeight, blockHash.Hex()[:12], len(b.Txs))

    go bc.notifyNewBlock(b)

    return nil
}

// handleSyncModeBlock handles blocks during sync mode
func (bc *Blockchain) handleSyncModeBlock(b *block.Block, blockHash common.Hash,
    blockHeight uint64, parentBlock *block.Block) error {

    // Validate and execute block
    if err := bc.validateAndExecuteBlock(b, parentBlock); err != nil {
        return fmt.Errorf("sync block validation and execution failed: %w", err)
    }

    // Add to database first
    if err := bc.db.WriteBlock(b); err != nil {
        return fmt.Errorf("failed to write sync block to database: %w", err)
    }

    // Update canonical tip if this advances the chain
    currentTip := bc.latest.Load()
    currentHeight := uint64(0)
    if currentTip != nil {
        currentHeight = currentTip.Header.Number.Uint64()
    }

    if blockHeight > currentHeight {
        if err := bc.db.WriteHeadBlockHash(blockHash); err != nil {
            log.Printf("[blockchain] Warning: failed to update head block hash during sync: %v", err)
        }
    }

    // Add to chain (write lock)
    bc.stateMu.Lock()

    // Update latest block pointer
    bc.latest.Store(b)
    bc.lastCanonicalHeight.Store(blockHeight)

    // Update cache
    bc.cacheMu.Lock()
    bc.blockByNumberCache.Add(blockHeight, b)
    bc.blockByHashCache.Add(blockHash, b)
    bc.cacheMu.Unlock()

    if bc.rotatingKingManager != nil {
        go bc.syncRotatingKingForBlock(blockHeight)
    }

    // Check if sync completed
    bc.maybeCompleteSync(blockHeight)
    bc.stateMu.Unlock()

    // Note: persistBlockAsync is now redundant but kept for compatibility
    go bc.persistBlockAsync(b)

    // Update rotating king database
    if bc.rotatingKingManager != nil {
        go bc.updateRotatingKingForBlock(b, blockHeight)
    }

    // Clean up mined transactions from pool
    if bc.txPool != nil && len(b.Txs) > 0 {
        bc.txPool.CleanupMinedTransactions(b.Txs)
        log.Printf("[blockchain] Cleaned up %d mined transactions from pool during sync", len(b.Txs))
    }

    // Log success
    log.Printf("[blockchain] Added sync block → height=%d hash=%s",
        blockHeight, blockHash.Hex())

    go bc.notifyNewBlock(b)

    return nil
}

// reorganizeAtHeight performs chain reorganization
func (bc *Blockchain) reorganizeAtHeight(height uint64, newBlock *block.Block) error {
    bc.stateMu.Lock()
    defer bc.stateMu.Unlock()

    // Get old block from cache or database
    oldBlock := bc.GetBlock(height)
    if oldBlock == nil {
        return fmt.Errorf("no block to replace at height %d", height)
    }

    oldHash := oldBlock.Hash()
    newHash := newBlock.Hash()

    log.Printf("[blockchain] Reorg: replacing block %s with %s at height %d",
        oldHash.Hex()[:12], newHash.Hex()[:12], height)

    // Write new block to database
    if err := bc.db.WriteBlock(newBlock); err != nil {
        return fmt.Errorf("failed to write new block to database during reorg: %w", err)
    }

    // Update canonical hash in database
    if err := bc.db.WriteCanonicalHash(height, newHash); err != nil {
        log.Printf("[blockchain] Warning: failed to update canonical hash during reorg: %v", err)
    }

    // Update head if this was the tip
    currentTip := bc.latest.Load()
    if currentTip != nil && currentTip.Hash() == oldHash {
        if err := bc.db.WriteHeadBlockHash(newHash); err != nil {
            log.Printf("[blockchain] Warning: failed to update head block hash during reorg: %v", err)
        }
    }

    // Update cache
    bc.cacheMu.Lock()
    // Remove old block from cache
    bc.blockByNumberCache.Remove(height)
    bc.blockByHashCache.Remove(oldHash)
    // Add new block to cache
    bc.blockByNumberCache.Add(height, newBlock)
    bc.blockByHashCache.Add(newHash, newBlock)
    bc.cacheMu.Unlock()

    // Update tip if this was the tip
    if currentTip != nil && currentTip.Hash() == oldHash {
        bc.latest.Store(newBlock)
    }

    // Note: persistBlockAsync is no longer needed for persistence but may do other things
    go bc.persistBlockAsync(newBlock)

    // Cleanup txs from old block, add from new
    if bc.txPool != nil {
        bc.txPool.CleanupMinedTransactions(oldBlock.Txs)
        // Note: We don't add new block's txs back to pool - they're already mined
    }

    log.Printf("[blockchain] Reorg successful at height %d", height)
    return nil
}

// triggerSyncFromBlock triggers sync from a block
func (bc *Blockchain) triggerSyncFromBlock(b *block.Block) {
    height := b.Header.Number.Uint64()
    if height <= bc.GetChainHeight() {
        return
    }
    bc.StartSync(height)
}

// maybeCompleteSync checks if sync is complete
func (bc *Blockchain) maybeCompleteSync(height uint64) {
    if !bc.syncing.Load() {
        return
    }

    target := bc.syncTarget.Load()
    if height >= target {
        if bc.syncing.Swap(false) {
            log.Printf("[blockchain] Sync completed! Reached height %d (target was %d)", height, target)
        }
    }
}

// ProcessSyncBatch processes multiple blocks during sync
func (bc *Blockchain) ProcessSyncBatch(blocks []*block.Block) error {
    if len(blocks) == 0 {
        return nil
    }

    // Sort blocks by height
    sort.Slice(blocks, func(i, j int) bool {
        return blocks[i].Header.Number.Uint64() < blocks[j].Header.Number.Uint64()
    })

    // ==============================================
    // VALIDATE BLOCKS AGAINST CP
    // ==============================================
    for _, block := range blocks {
        blockHeight := block.Header.Number.Uint64()
        blockHash := block.Hash()
        
        if bc.checkpointManager != nil {
            // Validate against checkpoint if exists
            if cp, exists := bc.checkpointManager.GetCheckpoint(blockHeight); exists {
                err := bc.checkpointManager.ValidateBlock(blockHeight, blockHash)
                if err != nil {
                    return fmt.Errorf("checkpoint validation failed for block %d: %w", blockHeight, err)
                }
                log.Printf("[blockchain] ✅ Sync block %d validated against checkpoint (verifications: %d)",
                    blockHeight, cp.Verifications)
            }
        }
    }
    // ==============================================
    // END CHECKPOINT VALIDATION
    // ==============================================

    // Use batch for database writes during sync
    batch := bc.db.DB().NewBatch()
    defer batch.Close()

    for _, block := range blocks {
        blockHeight := block.Header.Number.Uint64()
        blockHash := block.Hash()

        // Validate parent exists
        if blockHeight > 0 {
            parentBlock := bc.GetBlock(blockHeight - 1)
            if parentBlock == nil {
                return fmt.Errorf("missing parent for block %d", blockHeight)
            }

            if err := bc.validateAndExecuteBlock(block, parentBlock); err != nil {
                return fmt.Errorf("block %d validation failed: %w", blockHeight, err)
            }
        } else {
            // Genesis block validation
            if err := bc.validateAndExecuteBlock(block, nil); err != nil {
                return fmt.Errorf("genesis block validation failed: %w", err)
            }
        }

        // Write block to batch using RLP encoding
        blockData, err := rlp.EncodeToBytes(block)
        if err != nil {
            return fmt.Errorf("failed to encode block %d: %w", blockHeight, err)
        }

        batch.Set(db.BlockByHashKey(blockHash), blockData, pebble.Sync)

        // Write header using RLP encoding
        headerData, err := rlp.EncodeToBytes(block.Header)
        if err != nil {
            return fmt.Errorf("failed to encode header for block %d: %w", blockHeight, err)
        }
        batch.Set(db.HeaderByNumberKey(blockHeight), headerData, pebble.Sync)
        batch.Set(db.HeaderByHashKey(blockHash), headerData, pebble.Sync)

        // Update canonical pointer
        batch.Set(db.CanonicalHashKey(blockHeight), blockHash[:], pebble.Sync)
    }

    // Commit batch to database
    if err := batch.Commit(pebble.Sync); err != nil {
        return fmt.Errorf("failed to commit sync batch: %w", err)
    }

    // Update head block hash after batch commit
    if len(blocks) > 0 {
        latestBlock := blocks[len(blocks)-1]
        if err := bc.db.WriteHeadBlockHash(latestBlock.Hash()); err != nil {
            log.Printf("[blockchain] Warning: failed to update head block hash after batch sync: %v", err)
        }
    }

    // Update cache and latest pointer
    bc.stateMu.Lock()
    for _, block := range blocks {
        blockHeight := block.Header.Number.Uint64()
        blockHash := block.Hash()
        
        bc.cacheMu.Lock()
        bc.blockByNumberCache.Add(blockHeight, block)
        bc.blockByHashCache.Add(blockHash, block)
        bc.cacheMu.Unlock()
    }
    
    // Update latest block pointer
    latestBlock := blocks[len(blocks)-1]
    bc.latest.Store(latestBlock)
    bc.lastCanonicalHeight.Store(latestBlock.Header.Number.Uint64())
    bc.stateMu.Unlock()

    log.Printf("[blockchain] Processed sync batch of %d blocks", len(blocks))
    return nil
}

// StartSyncWithDatabase starts sync with database integration
func (bc *Blockchain) StartSyncWithDatabase(targetHeight uint64) error {
    log.Printf("[blockchain] Starting sync to height %d with database integration", targetHeight)

    bc.syncing.Store(true)
    bc.syncTarget.Store(targetHeight)

    // Start rotating king database sync in parallel
    if bc.rotatingKingManager != nil {
        go bc.syncRotatingKingDatabase(targetHeight)
    }

    log.Printf("[blockchain] Sync mode ENABLED → target height = %d", targetHeight)
    return nil
}

// notifyNewBlock notifies miners of new block
func (bc *Blockchain) notifyNewBlock(b *block.Block) {
    log.Printf("[blockchain] New block notification: height=%d hash=%s",
        b.Header.Number.Uint64(), b.Hash().Hex()[:10])
}

// syncRotatingKingForBlock syncs rotating king database for a block
func (bc *Blockchain) syncRotatingKingForBlock(blockHeight uint64) {
    if bc.rotatingKingManager != nil {
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        
        if err := bc.rotatingKingManager.SyncBlocks(ctx, blockHeight); err != nil {
            log.Printf("[blockchain] Failed to sync rotating king for block %d: %v", blockHeight, err)
        }
    }
}

// syncRotatingKingDatabase syncs rotating king database
func (bc *Blockchain) syncRotatingKingDatabase(targetHeight uint64) {
    if bc.rotatingKingManager != nil {
        ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
        defer cancel()
        
        if err := bc.rotatingKingManager.SyncBlocks(ctx, targetHeight); err != nil {
            log.Printf("[blockchain] Failed to sync rotating king database: %v", err)
        }
    }
}

// updateRotatingKingForBlock updates rotating king for a block
func (bc *Blockchain) updateRotatingKingForBlock(b *block.Block, blockHeight uint64) {
    if bc.rotatingKingManager != nil {
        // Check if rotation should happen
        if bc.rotatingKingManager.ShouldRotate(blockHeight) {
            if err := bc.rotatingKingManager.RotateToNextKing(blockHeight, b.Hash()); err != nil {
                log.Printf("[blockchain] Failed to rotate king at block %d: %v", blockHeight, err)
            }
        }
    }
}

// persistBlockAsync - kept for compatibility
func (bc *Blockchain) persistBlockAsync(b *block.Block) {
    // This is now a no-op since persistence is handled by db.WriteBlock
    // But kept for compatibility with code that might call it
    log.Printf("[blockchain] Block %d persisted to database", b.Header.Number.Uint64())
}

// ==============================================
// CHECKPOINT HELPER METHODS
// ==============================================

// shouldCreateCheckpoint determines if a checkpoint should be created at this height
func (bc *Blockchain) shouldCreateCheckpoint(height uint64) bool {
    // Create checkpoints:
    // 1. At genesis (height 0)
    // 2. Every 1000 blocks
    // 3. Every 10000 blocks (major checkpoint)
    // 4. Optionally at block 1 for initial validation
    if height == 0 {
        return true
    }
    
    // Checkpoint at block 1 for initial chain validation
    if height == 1 {
        return true
    }
    
    // Regular checkpoints every 1000 blocks
    if height%1000 == 0 {
        return true
    }
    
    // Major checkpoints every 10000 blocks
    if height%10000 == 0 {
        return true
    }
    
    return false
}

// createCheckpointFromBlock creates a checkpoint from a block
func (bc *Blockchain) createCheckpointFromBlock(b *block.Block) error {
    if bc.checkpointManager == nil {
        return errors.New("checkpoint manager not initialized")
    }
    
    blockHeight := b.Header.Number.Uint64()
    blockHash := b.Hash()
    
    // Get rotating king address
    var rotatingKing common.Address
    if bc.rotatingKingManager != nil {
        rotatingKing = bc.rotatingKingManager.GetCurrentKing()
    }
    
    // Get parent hash
    parentHash := b.Header.ParentHash
    if blockHeight == 0 {
        parentHash = common.Hash{} // Genesis has no parent
    }
    
    // Get miner/coinbase
    miner := b.Header.Coinbase
    
    // Get transaction count
    txCount := len(b.Txs)
    
    // Estimate gas used (you might want to track this properly)
    gasUsed := uint64(0)
    if len(b.Txs) > 0 {
        // TODO:21000 per transaction
        gasUsed = uint64(len(b.Txs) * 21000)
    }
    
    // Add the checkpoint
    err := bc.checkpointManager.AddCheckpoint(
        blockHeight,
        blockHash,
        parentHash,
        miner,
        rotatingKing,
        txCount,
        gasUsed,
    )
    
    if err != nil {
        return fmt.Errorf("failed to add checkpoint at height %d: %w", blockHeight, err)
    }
    
    log.Printf("[blockchain] Checkpoint created at height %d (hash: %s)",
        blockHeight, blockHash.Hex()[:12])
    
    return nil
}

// ValidateBlockAgainstCheckpoints validates a block against any existing checkpoints
func (bc *Blockchain) ValidateBlockAgainstCheckpoints(height uint64, hash common.Hash) error {
    if bc.checkpointManager == nil {
        return nil // No checkpoint manager, skip validation
    }
    
    return bc.checkpointManager.ValidateBlock(height, hash)
}

// GetCheckpointManager returns the checkpoint manager
func (bc *Blockchain) GetCheckpointManager() *checkpoints.Checkpoints {
    return bc.checkpointManager
}

// SetCheckpointManager sets the checkpoint manager
func (bc *Blockchain) SetCheckpointManager(cp *checkpoints.Checkpoints) {
    bc.checkpointManager = cp
    log.Printf("[blockchain] Checkpoint manager configured")
}
