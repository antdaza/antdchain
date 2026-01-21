// Copyright © 2025 ANTDChain Contributors
// Licensed under the MIT License (MIT). See LICENSE in the repository root
// for more information.

package block

import (
    "encoding/binary"

    "github.com/ethereum/go-ethereum/common"
    "github.com/zeebo/blake3"
)

func HashForMining(h *Header) common.Hash {
    buf := make([]byte, 0, 256)

    appendBytes := func(b []byte) { buf = append(buf, b...) }
    appendU64 := func(v uint64) {
        tmp := make([]byte, 8)
        binary.LittleEndian.PutUint64(tmp, v)
        appendBytes(tmp)
    }
    appendBig32BE := func(b []byte) {
        // Normalize to exactly 32 bytes (big‑endian)
        if len(b) < 32 {
            pad := make([]byte, 32-len(b))
            b = append(pad, b...)
        } else if len(b) > 32 {
            b = b[len(b)-32:]
        }
        appendBytes(b)
    }

    // Serialize fields in fixed order
    appendBytes(h.ParentHash[:])
    appendBytes(h.Coinbase[:])
    appendBytes(h.Root[:])
    appendBytes(h.TxHash[:])
    appendU64(h.Number.Uint64())
    appendU64(uint64(h.GasLimit))
    appendU64(uint64(h.GasUsed))
    appendU64(h.Time)
    appendBig32BE(h.Difficulty.Bytes())

    // Extra: length (uint32 LE) + bytes
    extraLen := make([]byte, 4)
    binary.LittleEndian.PutUint32(extraLen, uint32(len(h.Extra)))
    appendBytes(extraLen)
    appendBytes(h.Extra)

    sum := blake3.Sum256(buf)
    return common.BytesToHash(sum[:])
}
