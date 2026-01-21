// Copyright © 2025 ANTDChain Contributors
// Licensed under the MIT License (MIT). See LICENSE in the repository root
// for more information.

package tx

import (
    "crypto/ecdsa"
    "crypto/sha256"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "math/big"
    "strings"
    "time"

    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/ethereum/go-ethereum/rlp"
)

// Tx represents a ANTDChain transaction.
type Tx struct {
    From     common.Address
    To       *common.Address
    Value    *big.Int
    Data     []byte
    Nonce    uint64
    Gas      uint64
    GasPrice *big.Int
    Sig      []byte
    Timestamp uint64          `json:"timestamp"`
}

// NewTx creates a new transaction.
func NewTx(from, to common.Address, value *big.Int, data []byte, nonce, gas uint64, gasPrice *big.Int) *Tx {
    return &Tx{From: from, To: &to, Value: value, Data: data, Nonce: nonce, Gas: gas, GasPrice: gasPrice}
}

// Serialize serializes the transaction.
func (tx *Tx) Serialize() ([]byte, error) {
    return rlp.EncodeToBytes(tx)
}

// Deserialize deserializes a transaction.
func Deserialize(data []byte) (*Tx, error) {
    var tx Tx
    if err := rlp.DecodeBytes(data, &tx); err != nil {
        return nil, err
    }
    return &tx, nil
}

// Sign signs the transaction with the private key.
func (tx *Tx) Sign(privKey *ecdsa.PrivateKey) error {
    hash := tx.Hash()
    sig, err := crypto.Sign(hash[:], privKey)
    if err != nil {
        return err
    }
    tx.Sig = sig
    tx.From = crypto.PubkeyToAddress(privKey.PublicKey)
    return nil
}

// Hash computes the transaction hash.
func (tx *Tx) Hash() common.Hash {
    hasher := sha256.New()
    if tx.To != nil {
        hasher.Write(tx.To[:])
    }
    hasher.Write(tx.Value.Bytes())
    hasher.Write(tx.Data)
    binary.Write(hasher, binary.BigEndian, tx.Nonce)
    binary.Write(hasher, binary.BigEndian, tx.Gas)
    hasher.Write(tx.GasPrice.Bytes())
    return common.BytesToHash(hasher.Sum(nil))
}

// Verify verifies the transaction signature.
func (tx *Tx) Verify() (bool, error) {
    hash := tx.Hash()
    pubKey, err := crypto.SigToPub(hash[:], tx.Sig)
    if err != nil {
        return false, err
    }
    addr := crypto.PubkeyToAddress(*pubKey)
    if addr != tx.From {
        return false, errors.New("invalid signature")
    }
    return true, nil
}

// Validate performs basic validation.
func (tx *Tx) Validate() error {
    if tx.Gas == 0 {
        return errors.New("zero gas")
    }
    if tx.GasPrice == nil || tx.GasPrice.Sign() <= 0 {
        return errors.New("invalid gas price")
    }
    if tx.Value == nil || tx.Value.Sign() < 0 {
        return errors.New("invalid value")
    }
    if len(tx.Sig) != 65 {
        return errors.New("invalid signature length")
    }
    return nil
}

// MarshalJSON marshals the transaction to JSON.
func (tx Tx) MarshalJSON() ([]byte, error) {
    var to *string
    if tx.To != nil {
        s := tx.To.Hex()
        to = &s
    }
    valStr := ""
    if tx.Value != nil {
        valStr = tx.Value.String()
    }
    gpStr := ""
    if tx.GasPrice != nil {
        gpStr = tx.GasPrice.String()
    }
    return json.Marshal(struct {
        From     string  `json:"from"`
        To       *string `json:"to"`
        Value    string  `json:"value"`
        Data     string  `json:"data"`
        Nonce    uint64  `json:"nonce"`
        Gas      uint64  `json:"gas"`
        GasPrice string  `json:"gasPrice"`
        Sig      string  `json:"sig"`
    }{
        From:     tx.From.Hex(),
        To:       to,
        Value:    valStr,
        Data:     hex.EncodeToString(tx.Data),
        Nonce:    tx.Nonce,
        Gas:      tx.Gas,
        GasPrice: gpStr,
        Sig:      hex.EncodeToString(tx.Sig),
    })
}

// UnmarshalJSON unmarshals the transaction from JSON with backward compatibility.
func (tx *Tx) UnmarshalJSON(data []byte) error {
    type Alias Tx
    type tempTx struct {
        *Alias
        Value     interface{} `json:"value"`
        GasPrice  interface{} `json:"gasPrice"`
        Data      string      `json:"data"`
        Sig       string      `json:"sig"`
        To        *string     `json:"to"`
    }
    aux := &tempTx{
        Alias: (*Alias)(tx),
    }

    if err := json.Unmarshal(data, aux); err != nil {
        return err
    }

    // Handle Data: hex string → []byte
    if aux.Data != "" {
        d, err := hex.DecodeString(aux.Data)
        if err != nil {
            return fmt.Errorf("invalid data hex: %w", err)
        }
        tx.Data = d
    }

    // Handle Sig: hex string → []byte
    if aux.Sig != "" {
        s, err := hex.DecodeString(aux.Sig)
        if err != nil {
            return fmt.Errorf("invalid sig hex: %w", err)
        }
        tx.Sig = s
    }

    // Handle To: string → *Address
    if aux.To != nil {
        addr := common.HexToAddress(*aux.To)
        tx.To = &addr
    }

    // parse big.Int from interface{}, handling strings, numbers, or malformed quoted strings
    parseBigInt := func(v interface{}) (*big.Int, error) {
        switch val := v.(type) {
        case float64:
            return big.NewInt(int64(val)), nil
        case string:
            // Trim outer quotes if present (handles "\"2\"" -> "2")
            cleaned := strings.Trim(val, "\"")
            if cleaned != val {
                // Log for debug (remove in prod if needed)
                fmt.Printf("Warning: Trimmed malformed string '%s' to '%s'\n", val, cleaned)
            }
            if cleaned == "" {
                return big.NewInt(0), nil
            }
            num, ok := new(big.Int).SetString(cleaned, 10)
            if !ok {
                return nil, fmt.Errorf("invalid big.Int string: %s", cleaned)
            }
            return num, nil
        case nil:
            return big.NewInt(0), nil
        default:
            return nil, fmt.Errorf("invalid type for big.Int: %T (%v)", v, v)
        }
    }

    // Handle Value
    if val, err := parseBigInt(aux.Value); err != nil {
        return fmt.Errorf("invalid value: %w", err)
    } else {
        tx.Value = val
    }

    // Handle GasPrice
    if gp, err := parseBigInt(aux.GasPrice); err != nil {
        return fmt.Errorf("invalid gasPrice: %w", err)
    } else {
        tx.GasPrice = gp
    }

    return nil
}

// NewTransferTx creates a simple value transfer with timestamp
func NewTransferTx(from, to common.Address, amount *big.Int, nonce uint64, gasPrice *big.Int) *Tx {
    return &Tx{
        From:      from,
        To:        &to,
        Value:     amount,
        Data:      nil,
        Nonce:     nonce,
        Gas:       21000,
        GasPrice:  gasPrice,
        Timestamp: uint64(time.Now().Unix()),
    }
}
