package hd_wallet

type TD_Derive int

const (
	TD_Derive_Hardened TD_Derive = iota + 1
	TD_Derive_NonHardenedPriv
	TD_Derive_NonHardenedPub
)
