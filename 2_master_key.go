package hd_wallet

import (
	"github.com/gokch/crypto/hmac"

	"github.com/tyler-smith/go-bip39"
)

func MnemonicToSeed(mnemonic string) (seed []byte, err error) {
	return MnemonicToSeedWithPw(mnemonic, "")
}

func MnemonicToSeedWithPw(mnemonic string, pw string) (seed []byte, err error) {
	return bip39.NewSeedWithErrorChecking(mnemonic, pw)
}

func SeedToMasterKey(seed []byte) (masterKey []byte, chainCode []byte, err error) {
	return SeedToMasterKeyWithPw(seed, nil)
}

func SeedToMasterKeyWithPw(seed []byte, pw []byte) (masterKey []byte, chainCode []byte, err error) {
	hash, err := hmac.FromBytes(pw, seed)
	if err != nil {
		return nil, nil, err
	}
	half := len(hash) / 2
	masterKey = hash[:half]
	chainCode = hash[half:]

	return masterKey, chainCode, nil
}
