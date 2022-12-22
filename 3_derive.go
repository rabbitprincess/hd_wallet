package hd_wallet

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/gokch/crypto/hmac"
)

type DeriveType int

const (
	DeriveType_Hardened DeriveType = iota + 1
	DeriveType_NonHardenedPriv
	DeriveType_NonHardenedPub
)

const (
	defKeyLen = 33 // header( signal(1) ) + key(32) = 33
	defIdxLen = 4  // uint32(4)
)

func Derive(deriveType DeriveType, parentKey []byte, parentChaincode []byte, childIdx uint32) (childKey []byte, childChaincode []byte, err error) {
	// set parent key
	parentKeyWithIdx := make([]byte, defKeyLen+defIdxLen)
	switch deriveType {
	case DeriveType_Hardened:
		offset := defKeyLen - len(parentKey)
		copy(parentKeyWithIdx[offset:], parentKey)
	case DeriveType_NonHardenedPriv:
		_, pubkey := btcec.PrivKeyFromBytes(parentKey) // public key 를 찾는다
		copy(parentKeyWithIdx, pubkey.SerializeUncompressed())
	case DeriveType_NonHardenedPub:
		pubkey := parentKey
		copy(parentKeyWithIdx, pubkey)
	}
	binary.BigEndian.PutUint32(parentKeyWithIdx[defKeyLen:], childIdx)

	// set extended key
	childKeyExtended, err := hmac.FromBytes(parentChaincode, parentKeyWithIdx)
	if err != nil {
		return nil, nil, err
	}
	childKey = childKeyExtended[:len(childKeyExtended)/2]
	childChaincode = childKeyExtended[len(childKeyExtended)/2:]

	child := new(big.Int).SetBytes(childKey)

	// Both derived public or private keys rely on treating the left 32-byte
	// sequence calculated above (Il) as a 256-bit integer that must be
	// within the valid range for a secp256k1 private key.  There is a small
	// chance (< 1 in 2^127) this condition will not hold, and in that case,
	// a child extended key can't be created for this index and the caller
	// should simply increment to the next index.
	if child.Cmp(btcec.S256().N) >= 0 || child.Sign() == 0 {
		return nil, nil, fmt.Errorf("invalid child key | child key is too small, use next idx")
	}

	switch deriveType {
	case DeriveType_Hardened, DeriveType_NonHardenedPriv:
		parent := new(big.Int).SetBytes(parentKey)
		// child key = parse256(bt_privkey) + parentKey
		child.Add(child, parent)
		child.Mod(child, btcec.S256().N)
		childKey = child.Bytes()
	case DeriveType_NonHardenedPub:
		// get child x,y
		bigChildX, bigChildY := btcec.S256().ScalarBaseMult(childKey)
		if bigChildX.Sign() == 0 || bigChildY.Sign() == 0 {
			return nil, nil, fmt.Errorf("invalid child key")
		}
		// get parent x,y
		pubkey, err := btcec.ParsePubKey(parentKey)
		if err != nil {
			return nil, nil, err
		}
		bigParentX := pubkey.ToECDSA().X
		bigParentY := pubkey.ToECDSA().Y

		// Add the intermediate public key to the parent public key to derive the final child key.
		// child_key = serP(point(parse256(Il)) + parentKey)
		bigChildX, bigChildY = btcec.S256().Add(bigChildX, bigChildY, bigParentX, bigParentY)
		childX := &btcec.FieldVal{}
		childX.SetBytes((*[32]byte)(bigChildX.Bytes()))
		childY := &btcec.FieldVal{}
		childY.SetBytes((*[32]byte)(bigChildY.Bytes()))
		pubKey := btcec.NewPublicKey(childX, childY)
		childKey = pubKey.SerializeUncompressed()
	}

	return childKey, childChaincode, nil
}
