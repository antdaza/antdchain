// Copyright © 2025 ANTDChain Contributors
// Licensed under the MIT License (MIT). See LICENSE in the repository root
// for more information.

package chain

import (
    "math/big"
    "github.com/antdaza/antdchain/antdc/rotatingking"
    "github.com/ethereum/go-ethereum/common"
    )
// RotatingKingManager interface for managing rotating kings
type RotatingKingManager interface {
    GetCurrentKing() common.Address
    GetCurrentKingIndex() int
    GetKingAddresses() []common.Address
    IsKing(common.Address) bool
    ForceRotate(int, string) error
    GetRotationInterval() uint64
    GetRotationHistory(int) []interface{}
    GetKingRewardMultiplier() *big.Float
}


var _ rotatingking.BlockchainProvider = (*blockchainProviderWrapper)(nil)
