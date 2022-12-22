package hd_wallet

import (
	"fmt"

	"github.com/tyler-smith/go-bip39"
)

func MnemonicNew(len int) (mnemonic string, err error) {
	// 길이 전처리
	if len != 12 && len != 15 && len != 18 && len != 21 && len != 24 {
		return "", fmt.Errorf("mnemonic length must be 12,15,18,21,24 | input length : %d", len)
	}
	// get entrophy
	entropy, err := EntropyNew(len)
	if err != nil {
		return "", err
	}

	// get mnemonic
	return EntropyToMnemonic(entropy)
}

func EntropyNew(len int) (entropy []byte, err error) {
	// 길이 전처리
	if len != 12 && len != 15 && len != 18 && len != 21 && len != 24 {
		return nil, fmt.Errorf("mnemonic length must be 12,15,18,21,24 | input length : %d", len)
	}
	// get entrophy
	entropyLen := int(len) * 32 / 3
	entropy, err = bip39.NewEntropy(entropyLen)
	if err != nil {
		return nil, err
	}

	return entropy, nil
}

func MnemonicToEntropy(mnemonic string) (entropy []byte, err error) {
	return bip39.MnemonicToByteArray(mnemonic, true)
}

func EntropyToMnemonic(entropy []byte) (mnemonic string, err error) {
	return bip39.NewMnemonic(entropy)
}
