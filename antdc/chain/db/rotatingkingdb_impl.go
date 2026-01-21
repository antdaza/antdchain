// chain/db/rotatingkingdb_impl.go
package db

import (
    "bytes"
//    "context"
    "encoding/binary"
    "encoding/json"
    "errors"
    "fmt"
    "time"

    "github.com/cockroachdb/pebble"
    "github.com/ethereum/go-ethereum/common"
    "github.com/antdaza/antdchain/antdc/rotatingking"
)

// PebbleRotatingKingDB implements rotatingking.RotatingKingDatabase
type PebbleRotatingKingDB struct {
    db *pebble.DB
}

// NewPebbleRotatingKingDB creates a new rotating king database
func NewPebbleRotatingKingDB(db *pebble.DB) rotatingking.RotatingKingDatabase {
    return &PebbleRotatingKingDB{db: db}
}

// WriteRotatingKingState writes rotating king state
func (d *PebbleRotatingKingDB) WriteRotatingKingState(state *rotatingking.RotatingKingState) error {
    data, err := json.Marshal(state)
    if err != nil {
        return fmt.Errorf("failed to marshal rotating king state: %w", err)
    }
    return d.db.Set([]byte("rk_state"), data, pebble.Sync)
}

// ReadRotatingKingState reads rotating king state
func (d *PebbleRotatingKingDB) ReadRotatingKingState() (*rotatingking.RotatingKingState, error) {
    data, closer, err := d.db.Get([]byte("rk_state"))
    if err != nil {
        if errors.Is(err, pebble.ErrNotFound) {
            return nil, nil
        }
        return nil, err
    }
    defer closer.Close()

    var state rotatingking.RotatingKingState
    if err := json.Unmarshal(data, &state); err != nil {
        return nil, fmt.Errorf("failed to unmarshal rotating king state: %w", err)
    }
    return &state, nil
}

// WriteRotatingKingConfig writes rotating king configuration
func (d *PebbleRotatingKingDB) WriteRotatingKingConfig(config *rotatingking.RotatingKingConfig) error {
    data, err := json.Marshal(config)
    if err != nil {
        return fmt.Errorf("failed to marshal rotating king config: %w", err)
    }
    return d.db.Set([]byte("rk_config"), data, pebble.Sync)
}

// ReadRotatingKingConfig reads rotating king configuration
func (d *PebbleRotatingKingDB) ReadRotatingKingConfig() (*rotatingking.RotatingKingConfig, error) {
    data, closer, err := d.db.Get([]byte("rk_config"))
    if err != nil {
        if errors.Is(err, pebble.ErrNotFound) {
            return nil, nil
        }
        return nil, err
    }
    defer closer.Close()

    var config rotatingking.RotatingKingConfig
    if err := json.Unmarshal(data, &config); err != nil {
        return nil, fmt.Errorf("failed to unmarshal rotating king config: %w", err)
    }
    return &config, nil
}

// WriteRotationEvent writes a rotation event
func (d *PebbleRotatingKingDB) WriteRotationEvent(event *rotatingking.KingRotation) error {
    key := d.rotationEventKey(event.BlockHeight, event.NewKing)

    data, err := json.Marshal(event)
    if err != nil {
        return fmt.Errorf("failed to marshal rotation event: %w", err)
    }

    return d.db.Set(key, data, pebble.Sync)
}

// GetRotationEvents retrieves rotation events within a range
func (d *PebbleRotatingKingDB) GetRotationEvents(fromBlock, toBlock uint64) ([]rotatingking.KingRotation, error) {
    events := make([]rotatingking.KingRotation, 0)

    prefix := []byte("rk_event:")
    iter, err := d.db.NewIter(&pebble.IterOptions{
        LowerBound: prefix,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to create iterator: %w", err)
    }
    defer iter.Close()

    for iter.First(); iter.Valid(); iter.Next() {
        key := iter.Key()
        if !bytes.HasPrefix(key, prefix) {
            continue
        }

        // Parse block height from key: rk_event:[height]:[address]
        parts := bytes.Split(key, []byte(":"))
        if len(parts) < 3 {
            continue
        }

        height := binary.BigEndian.Uint64(parts[1])
        if height >= fromBlock && height <= toBlock {
            var event rotatingking.KingRotation
            if err := json.Unmarshal(iter.Value(), &event); err != nil {
                continue
            }
            events = append(events, event)
        }
    }

    return events, nil
}

// WriteBlockSyncRecord writes a block sync record
func (d *PebbleRotatingKingDB) WriteBlockSyncRecord(record *rotatingking.BlockSyncRecord) error {
    key := d.blockSyncRecordKey(record.BlockHeight)

    data, err := json.Marshal(record)
    if err != nil {
        return fmt.Errorf("failed to marshal block sync record: %w", err)
    }

    return d.db.Set(key, data, pebble.Sync)
}

// GetLastBlockSyncRecord gets the last block sync record
func (d *PebbleRotatingKingDB) GetLastBlockSyncRecord() (*rotatingking.BlockSyncRecord, error) {
    prefix := []byte("rk_sync:")
    var lastRecord *rotatingking.BlockSyncRecord
    var maxHeight uint64 = 0

    iter, err := d.db.NewIter(&pebble.IterOptions{
        LowerBound: prefix,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to create iterator: %w", err)
    }
    defer iter.Close()

    for iter.First(); iter.Valid(); iter.Next() {
        key := iter.Key()
        if !bytes.HasPrefix(key, prefix) {
            continue
        }

        parts := bytes.Split(key, []byte(":"))
        if len(parts) < 2 {
            continue
        }

        height := binary.BigEndian.Uint64(parts[1])
        if height > maxHeight {
            var record rotatingking.BlockSyncRecord
            if err := json.Unmarshal(iter.Value(), &record); err != nil {
                continue
            }
            lastRecord = &record
            maxHeight = height
        }
    }

    return lastRecord, nil
}

// WriteSyncState writes sync state
func (d *PebbleRotatingKingDB) WriteSyncState(state *rotatingking.SyncState) error {
    data, err := json.Marshal(state)
    if err != nil {
        return fmt.Errorf("failed to marshal sync state: %w", err)
    }
    return d.db.Set([]byte("rk_sync_state"), data, pebble.Sync)
}

// ReadSyncState reads sync state
func (d *PebbleRotatingKingDB) ReadSyncState() (*rotatingking.SyncState, error) {
    data, closer, err := d.db.Get([]byte("rk_sync_state"))
    if err != nil {
        if errors.Is(err, pebble.ErrNotFound) {
            return &rotatingking.SyncState{
                LastSyncedBlock: 0,
                LastSyncTime:    time.Time{},
                SyncProgress:    0,
                TotalBlocks:     0,
            }, nil
        }
        return nil, err
    }
    defer closer.Close()

    var state rotatingking.SyncState
    if err := json.Unmarshal(data, &state); err != nil {
        return nil, fmt.Errorf("failed to unmarshal sync state: %w", err)
    }
    return &state, nil
}

// GetMetrics returns database metrics
func (d *PebbleRotatingKingDB) GetMetrics() *rotatingking.DBMetrics {
    // Get actual database statistics if available
    var totalRecords, databaseSize int64
    
 
    return &rotatingking.DBMetrics{
        TotalRecords:       totalRecords,
        DatabaseSize:       databaseSize,
        DBSize:             databaseSize, // Same as DatabaseSize
        LastBackupTime:     time.Now(),
        SyncLatency:        0,
        WriteCount:         0,
        ReadCount:          0,
        BatchWriteSize:     0,
        LastWriteTime:      time.Now(),
        WriteLatency:       0,
        ReadLatency:        0,
        ActiveConnections:  0,
    }
}

// Close closes the database
func (d *PebbleRotatingKingDB) Close() error {
    // Note: We don't close the underlying Pebble DB here
    // as it's shared with ChainDB
    return nil
}

// Helper functions for key generation (make them methods to avoid conflicts)
func (d *PebbleRotatingKingDB) rotationEventKey(height uint64, address common.Address) []byte {
    key := make([]byte, 1+8+1+20)
    key[0] = 'r'
    key[1] = 'k'
    key[2] = '_'
    key[3] = 'e'
    key[4] = 'v'
    key[5] = 'e'
    key[6] = 'n'
    key[7] = 't'
    key[8] = ':'
    binary.BigEndian.PutUint64(key[9:17], height)
    key[17] = ':'
    copy(key[18:], address[:20])
    return key
}

func (d *PebbleRotatingKingDB) blockSyncRecordKey(height uint64) []byte {
    key := make([]byte, 1+8)
    key[0] = 'r'
    key[1] = 'k'
    key[2] = '_'
    key[3] = 's'
    key[4] = 'y'
    key[5] = 'n'
    key[6] = 'c'
    key[7] = ':'
    binary.BigEndian.PutUint64(key[8:], height)
    return key
}
