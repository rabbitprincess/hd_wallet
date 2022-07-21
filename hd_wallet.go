package hd_wallet

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/gokch/crypto/hmac"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/tyler-smith/go-bip39"
)

//---------------------------------------------------------------------------------------//
// common

func split_half(_bt_parent__key_priv []byte) (bt_child__key_priv []byte, bt_child__chaincode []byte) {
	if _bt_parent__key_priv == nil {
		return nil, nil
	}

	n_len__half := len(_bt_parent__key_priv) / 2
	bt_child__key_priv = _bt_parent__key_priv[:n_len__half]
	bt_child__chaincode = _bt_parent__key_priv[n_len__half:]
	return bt_child__key_priv, bt_child__chaincode
}

//---------------------------------------------------------------------------------------//
// mnemonic

func MnemonicNew(_len int) (mnemonicIdx []byte, err error) {
	// 길이 전처리
	if _len != 12 && _len != 15 && _len != 18 && _len != 21 && _len != 24 {
		return nil, fmt.Errorf("mnemonic length must be 12,15,18,21,24 | input length : %d", _len)
	}
	// get entrophy
	entropyLen := int(_len) * 32 / 3
	mnemonicIdx, err = bip39.NewEntropy(entropyLen)
	if err != nil {
		return nil, err
	}

	return mnemonicIdx, nil
}

func MnemonicEncode(_s_mnemonic string) (bt_mnemonic []byte, err error) {
	bt_mnemonic, err = bip39.MnemonicToByteArray(_s_mnemonic, true)
	if err != nil {
		return nil, err
	}
	return bt_mnemonic, nil
}

func MnemonicDecode(_bt_mnemonic []byte) (s_mnemonic string, err error) {
	s_mnemonic, err = bip39.NewMnemonic(_bt_mnemonic)
	if err != nil {
		return "", err
	}
	return s_mnemonic, nil
}

//---------------------------------------------------------------------------------------//
// seed

func SeedGet(_bt_mnemonic []byte, _pw string) (masterSeed []byte, err error) {
	s_mnemonic, err := MnemonicDecode(_bt_mnemonic)
	if err != nil {
		return nil, err
	}

	return bip39.NewSeedWithErrorChecking(s_mnemonic, _pw)
}

//---------------------------------------------------------------------------------------//
// master key

func MasterKeyGet(_seed []byte, _pw []byte) (masterKey []byte, chainCode []byte, err error) {
	hash, err := hmac.FromBytes(_pw, _seed)
	if err != nil {
		return nil, nil, err
	}
	half := len(hash) / 2
	masterKey = hash[:half]
	chainCode = hash[half:]

	return masterKey, chainCode, nil
}

//---------------------------------------------------------------------------------------//
// derive child

const (
	def_keyLen = 33 // header( signal(1) ) + key(32) = 33
	def_idxLen = 4  // uint32(4)
)

func Derive(_deriveType TD_Derive, _parentKey []byte, _parentChainCode []byte, _childIdx uint32) (childKey []byte, childChaincode []byte, err error) {
	// set parent key
	var parentKey_withIdx []byte
	{
		parentKey_withIdx = make([]byte, def_keyLen+def_idxLen)
		switch _deriveType {
		case TD_Derive_Hardened:
			offset := def_keyLen - len(_parentKey)
			copy(parentKey_withIdx[offset:], _parentKey)
		case TD_Derive_NonHardenedPriv:
			// public key 를 찾는다
			_, pubkey := btcec.PrivKeyFromBytes(_parentKey)
			copy(parentKey_withIdx, pubkey.SerializeUncompressed())
		case TD_Derive_NonHardenedPub:
			pubkey := _parentKey
			copy(parentKey_withIdx, pubkey)
		}

		binary.BigEndian.PutUint32(parentKey_withIdx[def_keyLen:], _childIdx)
	}

	// set extended key
	childKey_extended, err := hmac.FromBytes(_parentChainCode, parentKey_withIdx)
	if err != nil {
		return nil, nil, err
	}
	childKey, childChaincode = split_half(childKey_extended)

	bigChild := new(big.Int).SetBytes(childKey)
	// child key 후처리
	{
		// Both derived public or private keys rely on treating the left 32-byte
		// sequence calculated above (Il) as a 256-bit integer that must be
		// within the valid range for a secp256k1 private key.  There is a small
		// chance (< 1 in 2^127) this condition will not hold, and in that case,
		// a child extended key can't be created for this index and the caller
		// should simply increment to the next index.
		if bigChild.Cmp(btcec.S256().N) >= 0 || bigChild.Sign() == 0 {
			return nil, nil, fmt.Errorf("invalid child key | child key is too small, use next idx")
		}
	}

	switch _deriveType {
	case TD_Derive_Hardened, TD_Derive_NonHardenedPriv:
		{
			bigParent := new(big.Int).SetBytes(_parentKey)
			// child key = parse256(bt_privkey) + parentKey
			bigChild.Add(bigChild, bigParent)
			bigChild.Mod(bigChild, btcec.S256().N)
			childKey = bigChild.Bytes()
		}

	case TD_Derive_NonHardenedPub:
		{
			// get child x,y
			var bigChild_x, bigChild_y *big.Int
			{
				bigChild_x, bigChild_y = btcec.S256().ScalarBaseMult(childKey)
				if bigChild_x.Sign() == 0 || bigChild_y.Sign() == 0 {
					return nil, nil, fmt.Errorf("invalid child key")
				}
			}
			// get parent x,y
			var bigParent_x, bigParent_y *big.Int
			{

				pt_pubkey, err := btcec.ParsePubKey(_parentKey)
				if err != nil {
					return nil, nil, err
				}
				bigParent_x = pt_pubkey.ToECDSA().X
				bigParent_y = pt_pubkey.ToECDSA().Y
			}

			// Add the intermediate public key to the parent public key to derive the final child key.
			// child_key = serP(point(parse256(Il)) + parentKey)
			{
				bigChild_x, bigChild_y = btcec.S256().Add(bigChild_x, bigChild_y, bigParent_x, bigParent_y)
				ptChild_x := &btcec.FieldVal{}
				ptChild_x.SetBytes((*[32]byte)(bigChild_x.Bytes()))
				ptChild_y := &btcec.FieldVal{}
				ptChild_y.SetBytes((*[32]byte)(bigChild_y.Bytes()))
				pubKey := btcec.NewPublicKey(ptChild_x, ptChild_y)

				childKey = pubKey.SerializeUncompressed()
			}
		}
	}
	return childKey, childChaincode, nil
}
