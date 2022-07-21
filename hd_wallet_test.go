package hd_wallet

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/tyler-smith/go-bip39"
)

const (
	def_s_seed_key            = "test_seed_key"
	def_s_pw                  = "test_pw"
	def_s_mnemonic__12        = "feature burst special hospital miracle gesture alien pact large pumpkin media thought"
	def_s_mnemonic__24        = "couch amount cycle wall egg tank cabbage tower poem fringe yard birth when balcony vapor blade curtain seven lab light enhance weapon hero team"
	def_u4_test_idx__1 uint32 = 1
	def_u4_test_idx__2 uint32 = 5
	def_u4_test_idx__3 uint32 = 10
)

func Test__all(_t *testing.T) {
	// base test
	Test_MnemonicNew(_t)
	Test_MnemonicEncode(_t)
	Test_MnemonicDecode(_t)
	Test_SeedGet(_t)
	Test_MasterGet(_t)
	Test_ChildGet(_t)

	// advance test
	Test_MnemonicEncodeDecode(_t)
	Test_Seed_MasterKey(_t)
}

//-----------------------------------------------------------------//
// base test

func Test_MnemonicNew(_t *testing.T) {
	fn_get_len__entropy := func(_lenMnemonic int) (lenEntropy int) {
		lenEntropy = int(_lenMnemonic) * 32 / 24
		return lenEntropy
	}

	fn_test_mnemonic_len := func(_len int) {
		bt_mnemonic, err := MnemonicNew(_len)
		if err != nil {
			_t.Fatal(err)
		}
		if len(bt_mnemonic) != fn_get_len__entropy(_len) {
			_t.Errorf("len(bt_mnemonic) != n_len_mnemonic | len(bt_mnemonic) : %v | n_len_mnemonic : %v\n", len(bt_mnemonic), fn_get_len__entropy(_len))
		}
	}
	fn_test_mnemonic_len(12)
	fn_test_mnemonic_len(24)
}

func Test_MnemonicDecode(_t *testing.T) {
	fn_test := func(_mnemonicInput string, _mnemonicExpect []byte) {
		bt_mnemonic, err := MnemonicEncode(_mnemonicInput)
		if err != nil {
			_t.Fatal(err)
		}
		if bytes.Equal(bt_mnemonic, _mnemonicExpect) != true {
			_t.Errorf("bt_mnemonic != _bt_mnemonic__expect | bt_mnemonic : %v | _bt_mnemonic__expect : %v\n", bt_mnemonic, _mnemonicExpect)
		}
	}
	// len 12
	fn_test(
		"bitter gadget energy suit dice toward shuffle kite educate fish run repeat",
		[]byte{22, 203, 213, 40, 108, 131, 215, 204, 49, 219, 217, 70, 138, 246, 245, 91},
	)
	fn_test(
		"shoot honey melt cruel model act program harsh giggle party frozen stumble",
		[]byte{198, 141, 166, 42, 154, 72, 232, 4, 234, 251, 74, 97, 244, 17, 118, 235},
	)
	fn_test(
		"youth year shuffle miracle hello brave mobile lizard legend focus until utility",
		[]byte{255, 127, 223, 29, 198, 182, 172, 54, 163, 156, 22, 127, 139, 71, 184, 248},
	)
	fn_test(
		"grant fade apology genius coach merry very entry sure husband prison cash",
		[]byte{101, 170, 56, 41, 176, 114, 203, 23, 124, 186, 93, 218, 13, 254, 172, 17},
	)
	fn_test(
		"sponsor pilot grain lift best ticket blame coconut strike flag mirror thrive",
		[]byte{210, 116, 157, 150, 64, 177, 85, 195, 69, 201, 103, 215, 11, 6, 54, 112},
	)
	fn_test(
		"head obvious slab arrange dentist media gentle cousin yellow giraffe case shrimp",
		[]byte{106, 19, 23, 43, 134, 35, 169, 20, 216, 73, 139, 255, 12, 68, 140, 227},
	)

	// len 24
	fn_test(
		"jungle wrist shy lottery grid horse reveal video close disorder faint mouse case wool bird people solve feed tennis force hurdle view reunion fit",
		[]byte{121, 31, 207, 30, 66, 6, 102, 219, 174, 31, 158, 43, 167, 237, 71, 200, 82, 51, 250, 133, 165, 22, 206, 234, 151, 124, 173, 134, 249, 231, 238, 18},
	)
	fn_test(
		"erosion bundle pupil dice ginger witness host grab long pumpkin layer time delay true vague consider draft album confirm trash tired object just raven",
		[]byte{76, 163, 202, 183, 158, 182, 33, 249, 91, 131, 42, 131, 213, 181, 249, 113, 35, 159, 210, 188, 41, 122, 65, 224, 188, 187, 243, 190, 43, 48, 30, 93},
	)
	fn_test(
		"muscle thing flower van fatigue office thumb enlist hammer rely bronze rotate wise jelly business army disease town either real agree alert honey soft",
		[]byte{145, 156, 21, 102, 120, 149, 61, 51, 56, 90, 86, 104, 150, 172, 114, 222, 31, 198, 239, 135, 192, 96, 63, 28, 201, 28, 89, 112, 80, 12, 91, 78},
	)
	fn_test(
		"report ride fall female lawsuit galaxy floor squirrel put find ancient dream poverty young bronze poem paper place chair cheese grace visual cry menu",
		[]byte{182, 247, 45, 72, 170, 119, 226, 189, 214, 94, 157, 174, 202, 212, 34, 33, 74, 145, 254, 135, 45, 56, 159, 244, 184, 151, 19, 150, 87, 233, 205, 76},
	)
	fn_test(
		"warfare maple loyal marine tennis vacuum nephew answer online country bid pilot mask ostrich jealous jelly theme deliver leader west book sea fuel hero",
		[]byte{247, 16, 242, 18, 68, 13, 243, 225, 37, 16, 77, 154, 230, 32, 88, 82, 120, 135, 57, 221, 227, 190, 224, 7, 65, 250, 124, 177, 153, 131, 215, 123},
	)
	fn_test(
		"body smooth hero lyrics plastic glare behave invest ritual lounge hedgehog used traffic gauge juice sign artist merge annual diamond code drastic meat hip",
		[]byte{24, 249, 157, 173, 66, 186, 96, 197, 133, 27, 175, 186, 144, 137, 170, 119, 238, 108, 193, 30, 54, 66, 13, 17, 108, 37, 158, 146, 208, 132, 162, 131},
	)
}

func Test_MnemonicEncode(_t *testing.T) {
	fn_test := func(_bt_mnemonic__input []byte, _s_mnemonic__expect string) {
		s_mnemonic, err := MnemonicDecode(_bt_mnemonic__input)
		if err != nil {
			_t.Fatal(err)
		}
		if s_mnemonic != _s_mnemonic__expect {
			_t.Errorf("s_mnemonic != _s_mnemonic__expect | s_mnemonic : %v | _s_mnemonic__expect : %v\n", s_mnemonic, _s_mnemonic__expect)
		}
	}
	// len 12
	fn_test(
		[]byte{22, 203, 213, 40, 108, 131, 215, 204, 49, 219, 217, 70, 138, 246, 245, 91},
		"bitter gadget energy suit dice toward shuffle kite educate fish run repeat",
	)
	fn_test(
		[]byte{198, 141, 166, 42, 154, 72, 232, 4, 234, 251, 74, 97, 244, 17, 118, 235},
		"shoot honey melt cruel model act program harsh giggle party frozen stumble",
	)
	fn_test(
		[]byte{255, 127, 223, 29, 198, 182, 172, 54, 163, 156, 22, 127, 139, 71, 184, 248},
		"youth year shuffle miracle hello brave mobile lizard legend focus until utility",
	)
	fn_test(
		[]byte{101, 170, 56, 41, 176, 114, 203, 23, 124, 186, 93, 218, 13, 254, 172, 17},
		"grant fade apology genius coach merry very entry sure husband prison cash",
	)
	fn_test(
		[]byte{210, 116, 157, 150, 64, 177, 85, 195, 69, 201, 103, 215, 11, 6, 54, 112},
		"sponsor pilot grain lift best ticket blame coconut strike flag mirror thrive",
	)
	fn_test(
		[]byte{106, 19, 23, 43, 134, 35, 169, 20, 216, 73, 139, 255, 12, 68, 140, 227},
		"head obvious slab arrange dentist media gentle cousin yellow giraffe case shrimp",
	)

	// len 24
	fn_test(
		[]byte{121, 31, 207, 30, 66, 6, 102, 219, 174, 31, 158, 43, 167, 237, 71, 200, 82, 51, 250, 133, 165, 22, 206, 234, 151, 124, 173, 134, 249, 231, 238, 18},
		"jungle wrist shy lottery grid horse reveal video close disorder faint mouse case wool bird people solve feed tennis force hurdle view reunion fit",
	)
	fn_test(
		[]byte{76, 163, 202, 183, 158, 182, 33, 249, 91, 131, 42, 131, 213, 181, 249, 113, 35, 159, 210, 188, 41, 122, 65, 224, 188, 187, 243, 190, 43, 48, 30, 93},
		"erosion bundle pupil dice ginger witness host grab long pumpkin layer time delay true vague consider draft album confirm trash tired object just raven",
	)
	fn_test(
		[]byte{145, 156, 21, 102, 120, 149, 61, 51, 56, 90, 86, 104, 150, 172, 114, 222, 31, 198, 239, 135, 192, 96, 63, 28, 201, 28, 89, 112, 80, 12, 91, 78},
		"muscle thing flower van fatigue office thumb enlist hammer rely bronze rotate wise jelly business army disease town either real agree alert honey soft",
	)
	fn_test(
		[]byte{182, 247, 45, 72, 170, 119, 226, 189, 214, 94, 157, 174, 202, 212, 34, 33, 74, 145, 254, 135, 45, 56, 159, 244, 184, 151, 19, 150, 87, 233, 205, 76},
		"report ride fall female lawsuit galaxy floor squirrel put find ancient dream poverty young bronze poem paper place chair cheese grace visual cry menu",
	)
	fn_test(
		[]byte{247, 16, 242, 18, 68, 13, 243, 225, 37, 16, 77, 154, 230, 32, 88, 82, 120, 135, 57, 221, 227, 190, 224, 7, 65, 250, 124, 177, 153, 131, 215, 123},
		"warfare maple loyal marine tennis vacuum nephew answer online country bid pilot mask ostrich jealous jelly theme deliver leader west book sea fuel hero",
	)
	fn_test(
		[]byte{24, 249, 157, 173, 66, 186, 96, 197, 133, 27, 175, 186, 144, 137, 170, 119, 238, 108, 193, 30, 54, 66, 13, 17, 108, 37, 158, 146, 208, 132, 162, 131},
		"body smooth hero lyrics plastic glare behave invest ritual lounge hedgehog used traffic gauge juice sign artist merge annual diamond code drastic meat hip",
	)
}

func Test_SeedGet(_t *testing.T) {
	fn_test := func(_bt_mnemonic__input []byte, _s_pw__input string, _bt_seed__expect []byte) {
		bt_seed, err := SeedGet(_bt_mnemonic__input, _s_pw__input)
		if err != nil {
			_t.Fatal(err)
		}
		if bytes.Equal(bt_seed, _bt_seed__expect) != true {
			_t.Errorf("bt_seed != _bt_seed__expect | bt_seed : %v | _bt_seed__expect : %v\n", bt_seed, _bt_seed__expect)
		}
	}

	fn_test(
		[]byte{22, 203, 213, 40, 108, 131, 215, 204, 49, 219, 217, 70, 138, 246, 245, 91},
		def_s_seed_key,
		[]byte{190, 147, 251, 64, 32, 241, 220, 165, 33, 182, 205, 144, 95, 160, 119, 199, 11, 150, 168, 2, 68, 26, 202, 46, 71, 210, 225, 100, 188, 201, 178, 237, 24, 5, 106, 20, 53, 70, 208, 95, 65, 216, 102, 61, 100, 36, 246, 210, 137, 201, 63, 77, 35, 234, 3, 95, 171, 190, 190, 23, 119, 215, 42, 111},
	)
	fn_test(
		[]byte{198, 141, 166, 42, 154, 72, 232, 4, 234, 251, 74, 97, 244, 17, 118, 235},
		def_s_seed_key,
		[]byte{129, 105, 252, 206, 180, 178, 246, 161, 219, 27, 134, 150, 84, 165, 48, 44, 211, 115, 7, 26, 187, 92, 0, 132, 249, 188, 0, 60, 154, 225, 100, 247, 156, 44, 243, 91, 39, 243, 217, 103, 27, 90, 133, 48, 224, 3, 191, 73, 19, 152, 250, 54, 156, 175, 167, 5, 167, 243, 122, 58, 212, 244, 125, 68},
	)
	fn_test(
		[]byte{255, 127, 223, 29, 198, 182, 172, 54, 163, 156, 22, 127, 139, 71, 184, 248},
		def_s_seed_key,
		[]byte{228, 207, 82, 165, 48, 223, 103, 49, 197, 230, 72, 170, 252, 58, 215, 91, 128, 197, 165, 30, 60, 77, 161, 138, 221, 114, 195, 98, 176, 223, 1, 154, 193, 73, 192, 211, 91, 219, 39, 35, 74, 180, 245, 195, 1, 53, 78, 89, 189, 67, 110, 96, 143, 139, 9, 75, 196, 153, 215, 151, 129, 82, 203, 84},
	)
	fn_test(
		[]byte{101, 170, 56, 41, 176, 114, 203, 23, 124, 186, 93, 218, 13, 254, 172, 17},
		def_s_seed_key,
		[]byte{233, 0, 107, 216, 37, 213, 135, 170, 107, 191, 213, 20, 116, 105, 67, 6, 194, 210, 93, 93, 251, 194, 127, 50, 69, 4, 72, 131, 116, 85, 153, 135, 2, 254, 201, 236, 67, 117, 103, 174, 155, 90, 118, 213, 73, 118, 188, 219, 6, 119, 36, 189, 183, 173, 237, 217, 43, 11, 227, 158, 248, 251, 232, 193},
	)
	fn_test(
		[]byte{210, 116, 157, 150, 64, 177, 85, 195, 69, 201, 103, 215, 11, 6, 54, 112},
		def_s_seed_key,
		[]byte{164, 132, 108, 150, 12, 53, 112, 118, 125, 161, 252, 99, 212, 87, 200, 32, 185, 239, 131, 61, 124, 167, 161, 37, 199, 120, 62, 10, 102, 47, 7, 235, 198, 59, 221, 120, 31, 14, 70, 13, 170, 53, 33, 99, 175, 28, 196, 64, 65, 14, 138, 131, 131, 48, 52, 46, 235, 156, 248, 76, 119, 51, 40, 75},
	)
	fn_test(
		[]byte{106, 19, 23, 43, 134, 35, 169, 20, 216, 73, 139, 255, 12, 68, 140, 227},
		def_s_seed_key,
		[]byte{116, 225, 75, 107, 30, 59, 25, 248, 119, 69, 97, 90, 40, 45, 99, 55, 209, 88, 86, 164, 95, 165, 242, 59, 118, 77, 107, 49, 179, 52, 24, 224, 122, 249, 96, 249, 48, 236, 179, 70, 246, 54, 72, 21, 18, 173, 221, 98, 63, 243, 183, 41, 247, 175, 93, 61, 70, 229, 139, 63, 155, 142, 43, 161},
	)

	// len 24
	fn_test([]byte{121, 31, 207, 30, 66, 6, 102, 219, 174, 31, 158, 43, 167, 237, 71, 200, 82, 51, 250, 133, 165, 22, 206, 234, 151, 124, 173, 134, 249, 231, 238, 18},
		def_s_seed_key,
		[]byte{29, 198, 104, 200, 128, 14, 78, 203, 205, 69, 10, 242, 244, 44, 20, 98, 244, 166, 210, 180, 247, 207, 189, 192, 177, 170, 200, 249, 200, 169, 4, 133, 128, 98, 198, 57, 245, 65, 234, 207, 53, 23, 81, 228, 84, 212, 180, 50, 68, 206, 167, 4, 89, 161, 144, 162, 201, 203, 250, 146, 184, 177, 12, 166},
	)
	fn_test([]byte{76, 163, 202, 183, 158, 182, 33, 249, 91, 131, 42, 131, 213, 181, 249, 113, 35, 159, 210, 188, 41, 122, 65, 224, 188, 187, 243, 190, 43, 48, 30, 93},
		def_s_seed_key,
		[]byte{231, 105, 239, 188, 231, 232, 245, 28, 157, 14, 191, 154, 98, 7, 205, 67, 19, 11, 19, 101, 174, 230, 161, 172, 72, 21, 12, 178, 64, 60, 138, 52, 34, 101, 93, 135, 210, 211, 239, 75, 118, 158, 183, 229, 175, 75, 48, 128, 178, 76, 148, 207, 211, 122, 124, 251, 128, 53, 8, 158, 25, 241, 200, 193},
	)
	fn_test([]byte{145, 156, 21, 102, 120, 149, 61, 51, 56, 90, 86, 104, 150, 172, 114, 222, 31, 198, 239, 135, 192, 96, 63, 28, 201, 28, 89, 112, 80, 12, 91, 78},
		def_s_seed_key,
		[]byte{169, 49, 194, 95, 107, 52, 186, 252, 4, 229, 69, 30, 31, 198, 226, 36, 3, 169, 125, 82, 178, 112, 77, 172, 123, 212, 130, 181, 242, 212, 197, 144, 207, 6, 171, 244, 122, 129, 24, 100, 160, 253, 45, 211, 94, 167, 5, 221, 232, 132, 219, 223, 254, 132, 223, 131, 234, 68, 232, 82, 6, 192, 193, 34},
	)
	fn_test([]byte{182, 247, 45, 72, 170, 119, 226, 189, 214, 94, 157, 174, 202, 212, 34, 33, 74, 145, 254, 135, 45, 56, 159, 244, 184, 151, 19, 150, 87, 233, 205, 76},
		def_s_seed_key,
		[]byte{123, 149, 197, 118, 38, 64, 21, 43, 213, 85, 161, 9, 4, 180, 28, 210, 86, 48, 4, 77, 1, 210, 34, 69, 150, 9, 107, 221, 228, 185, 32, 38, 46, 185, 179, 244, 210, 159, 90, 2, 178, 12, 186, 226, 221, 252, 45, 243, 58, 49, 155, 175, 87, 181, 204, 138, 85, 213, 245, 118, 114, 242, 187, 82},
	)
	fn_test([]byte{247, 16, 242, 18, 68, 13, 243, 225, 37, 16, 77, 154, 230, 32, 88, 82, 120, 135, 57, 221, 227, 190, 224, 7, 65, 250, 124, 177, 153, 131, 215, 123},
		def_s_seed_key,
		[]byte{206, 203, 46, 17, 188, 37, 142, 240, 220, 4, 7, 90, 55, 223, 54, 56, 165, 143, 201, 207, 153, 45, 166, 78, 81, 98, 42, 65, 52, 165, 183, 234, 76, 191, 87, 145, 56, 5, 54, 118, 61, 243, 22, 241, 72, 105, 207, 60, 128, 199, 58, 248, 0, 86, 29, 174, 196, 46, 77, 134, 125, 213, 188, 221},
	)
	fn_test([]byte{24, 249, 157, 173, 66, 186, 96, 197, 133, 27, 175, 186, 144, 137, 170, 119, 238, 108, 193, 30, 54, 66, 13, 17, 108, 37, 158, 146, 208, 132, 162, 131},
		def_s_seed_key,
		[]byte{48, 212, 84, 3, 97, 35, 138, 20, 93, 130, 255, 114, 201, 195, 102, 75, 243, 165, 61, 145, 97, 124, 73, 31, 121, 39, 26, 186, 0, 61, 19, 60, 72, 230, 228, 134, 112, 245, 92, 246, 124, 13, 147, 157, 161, 45, 74, 147, 201, 66, 248, 173, 0, 162, 135, 81, 183, 171, 13, 60, 157, 242, 136, 71},
	)
}

func Test_MasterGet(_t *testing.T) {
	fn_test := func(_bt_seed__input []byte, _bt_key__input []byte, _bt_private_key__expect []byte, _bt_chaincode__expect []byte) {
		bt_private_key, bt_chaincode, err := MasterKeyGet(_bt_seed__input, _bt_key__input)
		if err != nil {
			_t.Fatal(err)
		}

		if bytes.Equal(bt_private_key, _bt_private_key__expect) != true {
			_t.Errorf("bt_private_key: %v != %v", bt_private_key, _bt_private_key__expect)
		}
		if bytes.Equal(bt_chaincode, _bt_chaincode__expect) != true {
			_t.Errorf("bt_chaincode: %v != %v", bt_chaincode, _bt_chaincode__expect)
		}
	}

	fn_test(
		[]byte{87, 175, 141, 136, 179, 33, 159, 172, 94, 239, 219, 52, 249, 169, 22, 37, 194, 41, 55, 224, 104, 118, 197, 230, 164, 247, 0, 96, 146, 113, 2, 223, 240, 183, 129, 241, 180, 38, 76, 252, 34, 157, 62, 34, 44, 49, 108, 53, 47, 113, 244, 109, 46, 141, 64, 110, 124, 51, 70, 169, 185, 148, 211, 222},
		[]byte(def_s_pw),
		[]byte{3, 113, 96, 67, 18, 114, 186, 50, 200, 252, 105, 229, 184, 44, 209, 144, 104, 78, 144, 118, 213, 131, 84, 36, 114, 11, 118, 212, 33, 232, 10, 1},
		[]byte{33, 82, 138, 42, 76, 217, 246, 170, 72, 162, 61, 81, 118, 230, 42, 8, 138, 191, 23, 131, 236, 131, 129, 106, 198, 87, 237, 39, 10, 142, 206, 84},
	)
	fn_test(
		[]byte{198, 73, 236, 210, 20, 214, 151, 116, 124, 26, 216, 234, 174, 251, 131, 28, 109, 170, 242, 120, 141, 184, 77, 180, 17, 23, 143, 68, 20, 218, 186, 210, 61, 182, 79, 162, 100, 80, 116, 32, 53, 192, 80, 77, 191, 66, 70, 79, 202, 106, 130, 227, 152, 167, 122, 175, 4, 227, 204, 170, 151, 216, 83, 223},
		[]byte(def_s_pw),
		[]byte{157, 124, 222, 169, 228, 33, 197, 31, 250, 38, 84, 95, 11, 159, 250, 253, 75, 222, 64, 211, 47, 250, 170, 226, 93, 235, 106, 218, 59, 134, 136, 27},
		[]byte{88, 2, 6, 165, 15, 247, 20, 96, 248, 184, 172, 83, 180, 146, 187, 66, 46, 194, 102, 70, 235, 202, 176, 82, 189, 103, 54, 10, 182, 3, 53, 2},
	)
	fn_test(
		[]byte{103, 95, 127, 16, 29, 16, 187, 94, 154, 10, 21, 190, 97, 22, 12, 77, 202, 136, 254, 125, 62, 123, 173, 187, 237, 184, 177, 211, 218, 163, 157, 146, 222, 209, 22, 82, 81, 14, 117, 56, 49, 200, 155, 160, 151, 170, 135, 125, 216, 201, 137, 91, 7, 88, 171, 163, 177, 13, 121, 198, 143, 47, 140, 139},
		[]byte(def_s_pw),
		[]byte{20, 62, 195, 199, 217, 57, 21, 82, 91, 212, 10, 250, 113, 124, 241, 151, 67, 22, 113, 180, 122, 235, 137, 5, 133, 120, 204, 217, 94, 240, 152, 50},
		[]byte{146, 88, 7, 180, 20, 5, 133, 151, 215, 125, 31, 132, 148, 186, 155, 208, 103, 33, 157, 65, 184, 122, 72, 80, 61, 161, 128, 62, 41, 0, 235, 147},
	)
	fn_test(
		[]byte{183, 218, 214, 57, 253, 91, 124, 99, 23, 215, 207, 169, 200, 73, 147, 247, 1, 19, 183, 121, 24, 160, 50, 252, 92, 224, 135, 169, 9, 153, 194, 38, 67, 182, 222, 223, 18, 58, 190, 239, 221, 55, 194, 12, 165, 50, 158, 68, 93, 135, 71, 214, 180, 32, 156, 214, 180, 133, 223, 182, 130, 77, 209, 219},
		[]byte(def_s_pw),
		[]byte{187, 104, 131, 250, 245, 134, 215, 39, 61, 172, 55, 87, 16, 138, 215, 180, 83, 211, 163, 101, 80, 148, 206, 65, 216, 124, 115, 218, 232, 38, 34, 205},
		[]byte{206, 175, 18, 254, 153, 135, 235, 19, 1, 23, 232, 35, 149, 164, 220, 250, 212, 203, 93, 0, 107, 231, 251, 23, 186, 110, 254, 180, 9, 188, 57, 161},
	)
	fn_test(
		[]byte{185, 254, 80, 154, 88, 39, 204, 131, 130, 87, 183, 158, 178, 24, 31, 227, 213, 8, 181, 142, 89, 223, 242, 170, 57, 112, 119, 178, 6, 145, 223, 255, 145, 24, 248, 206, 52, 63, 24, 4, 195, 224, 169, 1, 147, 25, 94, 98, 40, 154, 152, 157, 10, 6, 208, 172, 99, 89, 99, 160, 163, 250, 242, 12},
		[]byte(def_s_pw),
		[]byte{246, 177, 170, 116, 128, 153, 207, 59, 129, 128, 228, 144, 116, 104, 158, 43, 31, 253, 170, 226, 128, 50, 240, 232, 163, 226, 209, 158, 95, 55, 240, 219},
		[]byte{1, 62, 218, 141, 211, 11, 219, 182, 208, 255, 236, 8, 32, 172, 64, 139, 250, 242, 228, 79, 221, 58, 107, 188, 74, 247, 75, 221, 236, 78, 196, 132},
	)
	fn_test(
		[]byte{32, 16, 110, 199, 3, 161, 249, 117, 125, 21, 188, 102, 166, 185, 98, 235, 123, 231, 53, 187, 233, 200, 46, 177, 109, 34, 104, 132, 102, 87, 217, 26, 68, 116, 6, 140, 255, 126, 232, 161, 12, 51, 208, 105, 165, 78, 241, 203, 206, 161, 118, 57, 216, 89, 53, 229, 99, 251, 32, 95, 58, 155, 63, 50},
		[]byte(def_s_pw),
		[]byte{137, 141, 104, 102, 18, 141, 9, 69, 116, 140, 101, 36, 51, 149, 122, 238, 216, 200, 243, 170, 80, 0, 166, 191, 34, 36, 121, 85, 86, 70, 95, 211},
		[]byte{225, 64, 242, 23, 11, 198, 126, 25, 132, 216, 30, 253, 47, 235, 61, 17, 185, 171, 71, 138, 16, 214, 4, 204, 60, 61, 12, 190, 125, 71, 142, 249},
	)
	fn_test(
		[]byte{69, 145, 126, 153, 157, 212, 93, 254, 138, 203, 153, 211, 201, 8, 205, 97, 194, 218, 87, 114, 150, 177, 69, 241, 89, 93, 23, 138, 159, 175, 225, 33, 48, 163, 121, 53, 197, 108, 76, 8, 8, 186, 217, 224, 51, 100, 174, 185, 184, 75, 176, 143, 100, 84, 157, 44, 23, 207, 222, 179, 217, 81, 148, 251},
		[]byte(def_s_pw),
		[]byte{218, 75, 196, 143, 232, 94, 29, 144, 7, 239, 186, 210, 10, 142, 74, 180, 91, 79, 186, 137, 73, 187, 124, 235, 131, 187, 118, 108, 120, 87, 157, 198},
		[]byte{92, 237, 252, 162, 103, 156, 52, 114, 169, 179, 20, 227, 33, 107, 232, 126, 63, 56, 180, 71, 3, 198, 217, 231, 113, 59, 29, 102, 74, 81, 57, 71},
	)
	fn_test(
		[]byte{15, 82, 121, 162, 184, 8, 82, 171, 96, 210, 52, 107, 26, 223, 190, 29, 104, 55, 60, 182, 84, 135, 223, 172, 173, 117, 168, 186, 251, 253, 158, 3, 111, 219, 165, 188, 182, 101, 231, 21, 241, 212, 227, 44, 2, 118, 138, 13, 242, 237, 180, 100, 16, 10, 46, 177, 163, 232, 9, 159, 2, 98, 47, 140},
		[]byte(def_s_pw),
		[]byte{25, 28, 182, 30, 12, 236, 30, 97, 207, 238, 29, 76, 209, 125, 201, 156, 37, 163, 64, 98, 12, 204, 49, 149, 204, 142, 90, 232, 86, 205, 146, 158},
		[]byte{158, 20, 206, 179, 24, 76, 3, 39, 200, 91, 126, 12, 105, 203, 213, 27, 240, 169, 115, 180, 123, 162, 56, 96, 74, 35, 127, 83, 145, 212, 43, 41},
	)
	fn_test(
		[]byte{214, 98, 178, 216, 252, 102, 67, 160, 27, 89, 39, 124, 145, 255, 20, 103, 219, 217, 162, 20, 208, 87, 135, 227, 72, 242, 191, 114, 133, 209, 235, 54, 230, 31, 13, 188, 162, 192, 113, 238, 13, 199, 171, 230, 151, 74, 41, 160, 215, 192, 234, 117, 240, 156, 112, 212, 21, 184, 182, 137, 65, 252, 181, 115},
		[]byte(def_s_pw),
		[]byte{145, 28, 8, 106, 160, 186, 103, 235, 242, 134, 5, 113, 170, 237, 117, 110, 201, 74, 153, 183, 200, 227, 32, 87, 144, 228, 66, 79, 65, 240, 137, 14},
		[]byte{197, 184, 158, 155, 163, 143, 77, 122, 218, 143, 144, 152, 40, 183, 168, 145, 80, 77, 66, 165, 8, 190, 15, 244, 220, 2, 246, 67, 173, 140, 170, 234},
	)
	fn_test(
		[]byte{13, 122, 5, 254, 174, 203, 78, 97, 247, 203, 5, 63, 11, 207, 55, 49, 219, 45, 169, 229, 165, 30, 253, 82, 23, 67, 161, 171, 23, 219, 117, 204, 190, 202, 21, 49, 225, 137, 150, 23, 141, 234, 229, 253, 165, 200, 91, 70, 189, 115, 49, 45, 217, 147, 45, 65, 21, 119, 100, 193, 4, 33, 75, 95},
		[]byte(def_s_pw),
		[]byte{110, 134, 150, 23, 24, 81, 136, 82, 159, 37, 106, 98, 28, 168, 142, 180, 157, 144, 133, 130, 153, 122, 17, 101, 206, 46, 145, 158, 69, 201, 70, 255},
		[]byte{178, 61, 112, 120, 232, 137, 224, 200, 62, 69, 210, 157, 225, 127, 245, 39, 148, 233, 39, 135, 228, 173, 93, 103, 175, 155, 163, 6, 173, 211, 44, 205},
	)
	fn_test(
		[]byte{35, 189, 56, 29, 100, 185, 246, 238, 138, 232, 82, 96, 23, 31, 207, 213, 8, 50, 158, 9, 222, 192, 158, 90, 26, 210, 156, 49, 196, 171, 229, 11, 192, 105, 74, 47, 112, 135, 93, 190, 165, 30, 243, 104, 38, 209, 107, 86, 2, 29, 192, 28, 108, 252, 63, 61, 132, 241, 250, 246, 242, 65, 204, 6},
		[]byte(def_s_pw),
		[]byte{22, 144, 4, 53, 54, 171, 66, 66, 191, 23, 181, 215, 98, 8, 56, 55, 7, 86, 169, 167, 47, 244, 133, 246, 213, 175, 192, 119, 44, 28, 157, 207},
		[]byte{2, 150, 211, 155, 211, 131, 212, 78, 3, 171, 87, 246, 102, 143, 18, 192, 78, 33, 99, 61, 52, 66, 151, 208, 35, 179, 194, 102, 0, 9, 204, 240},
	)
	fn_test(
		[]byte{0, 198, 86, 120, 222, 149, 81, 242, 139, 193, 145, 101, 253, 91, 32, 214, 238, 241, 250, 3, 29, 231, 140, 92, 56, 250, 201, 44, 193, 98, 229, 6, 153, 133, 145, 110, 101, 210, 39, 134, 82, 216, 178, 208, 161, 168, 220, 146, 43, 112, 3, 89, 93, 154, 202, 163, 69, 127, 128, 245, 105, 232, 9, 9},
		[]byte(def_s_pw),
		[]byte{222, 23, 97, 45, 45, 40, 193, 72, 219, 129, 246, 187, 74, 41, 158, 188, 31, 144, 17, 71, 131, 250, 229, 226, 75, 133, 241, 155, 243, 105, 186, 52},
		[]byte{10, 108, 233, 190, 30, 54, 198, 109, 97, 77, 208, 81, 69, 212, 191, 233, 198, 18, 76, 105, 137, 18, 218, 4, 144, 214, 139, 118, 182, 73, 147, 144},
	)
}

func Test_ChildGet(_t *testing.T) {
	fn_test := func(_bt_key__input, _bt_chaincode__input []byte, _td_derive_type__input TD_Derive, _u4_idx__input uint32, _bt_child__key__expect []byte, _bt_child__chaincode__expect []byte) {
		bt_child_key, bt_child_chaincode, err := Derive(_td_derive_type__input, _bt_key__input, _bt_chaincode__input, _u4_idx__input)
		if err != nil {
			_t.Fatal(err)
		}

		// 두 값 비교
		if bytes.Equal(bt_child_key, _bt_child__key__expect) != true {
			_t.Errorf("invalid child key | result : %v | expect : %v", bt_child_key, _bt_child__key__expect)
		}
		if bytes.Equal(bt_child_chaincode, _bt_child__chaincode__expect) != true {
			_t.Errorf("invalid child chaincode | result : %v | expect : %v", bt_child_chaincode, _bt_child__chaincode__expect)
		}
	}

	// hardened private key
	fn_test(
		[]byte{127, 19, 169, 51, 36, 77, 221, 220, 35, 30, 99, 4, 237, 138, 92, 240, 134, 177, 114, 163, 210, 56, 158, 65, 106, 14, 123, 40, 2, 223, 48, 123},
		[]byte{73, 181, 191, 18, 41, 90, 225, 158, 90, 94, 40, 160, 159, 76, 153, 218, 103, 211, 41, 14, 70, 99, 249, 37, 197, 39, 115, 105, 159, 191, 84, 242},
		TD_Derive_Hardened,
		def_u4_test_idx__1,
		[]byte{40, 140, 136, 189, 173, 82, 171, 182, 78, 104, 112, 73, 38, 242, 51, 9, 59, 213, 241, 234, 211, 140, 80, 192, 118, 221, 223, 14, 17, 115, 217, 15},
		[]byte{56, 46, 99, 80, 88, 193, 110, 48, 135, 115, 65, 43, 34, 158, 14, 70, 97, 48, 198, 9, 235, 12, 139, 226, 99, 67, 191, 3, 111, 110, 210, 79},
	)
	fn_test(
		[]byte{127, 19, 169, 51, 36, 77, 221, 220, 35, 30, 99, 4, 237, 138, 92, 240, 134, 177, 114, 163, 210, 56, 158, 65, 106, 14, 123, 40, 2, 223, 48, 123},
		[]byte{73, 181, 191, 18, 41, 90, 225, 158, 90, 94, 40, 160, 159, 76, 153, 218, 103, 211, 41, 14, 70, 99, 249, 37, 197, 39, 115, 105, 159, 191, 84, 242},
		TD_Derive_Hardened,
		def_u4_test_idx__2,
		[]byte{228, 197, 194, 97, 210, 78, 27, 151, 17, 29, 107, 251, 112, 99, 16, 133, 211, 50, 255, 61, 10, 38, 1, 38, 91, 121, 165, 212, 223, 125, 29, 113},
		[]byte{53, 118, 5, 91, 106, 173, 60, 18, 248, 197, 227, 17, 153, 127, 122, 15, 231, 138, 40, 187, 164, 146, 8, 50, 176, 89, 27, 251, 147, 100, 180, 62},
	)
	fn_test(
		[]byte{127, 19, 169, 51, 36, 77, 221, 220, 35, 30, 99, 4, 237, 138, 92, 240, 134, 177, 114, 163, 210, 56, 158, 65, 106, 14, 123, 40, 2, 223, 48, 123},
		[]byte{73, 181, 191, 18, 41, 90, 225, 158, 90, 94, 40, 160, 159, 76, 153, 218, 103, 211, 41, 14, 70, 99, 249, 37, 197, 39, 115, 105, 159, 191, 84, 242},
		TD_Derive_Hardened,
		def_u4_test_idx__3,
		[]byte{78, 200, 178, 213, 157, 249, 32, 52, 222, 134, 218, 13, 221, 46, 33, 123, 109, 141, 22, 172, 93, 210, 238, 193, 232, 195, 189, 105, 116, 105, 100, 238},
		[]byte{237, 7, 189, 79, 171, 243, 11, 10, 40, 79, 52, 225, 61, 28, 42, 55, 157, 107, 11, 223, 213, 86, 144, 162, 131, 120, 49, 79, 195, 168, 228, 178},
	)

	// non hardened private key
	fn_test(
		[]byte{127, 19, 169, 51, 36, 77, 221, 220, 35, 30, 99, 4, 237, 138, 92, 240, 134, 177, 114, 163, 210, 56, 158, 65, 106, 14, 123, 40, 2, 223, 48, 123},
		[]byte{73, 181, 191, 18, 41, 90, 225, 158, 90, 94, 40, 160, 159, 76, 153, 218, 103, 211, 41, 14, 70, 99, 249, 37, 197, 39, 115, 105, 159, 191, 84, 242},
		TD_Derive_NonHardenedPriv,
		def_u4_test_idx__1,
		[]byte{148, 85, 94, 222, 243, 193, 115, 246, 189, 68, 239, 104, 170, 102, 213, 73, 125, 91, 164, 105, 77, 151, 117, 92, 104, 98, 79, 76, 143, 136, 194, 22},
		[]byte{46, 64, 239, 91, 21, 21, 85, 197, 154, 6, 214, 41, 66, 33, 173, 150, 178, 147, 165, 55, 64, 148, 238, 99, 32, 150, 166, 232, 18, 73, 1, 150},
	)
	fn_test(
		[]byte{127, 19, 169, 51, 36, 77, 221, 220, 35, 30, 99, 4, 237, 138, 92, 240, 134, 177, 114, 163, 210, 56, 158, 65, 106, 14, 123, 40, 2, 223, 48, 123},
		[]byte{73, 181, 191, 18, 41, 90, 225, 158, 90, 94, 40, 160, 159, 76, 153, 218, 103, 211, 41, 14, 70, 99, 249, 37, 197, 39, 115, 105, 159, 191, 84, 242},
		TD_Derive_NonHardenedPriv,
		def_u4_test_idx__2,
		[]byte{16, 95, 96, 105, 109, 132, 30, 22, 153, 67, 12, 221, 160, 66, 86, 0, 252, 177, 210, 84, 138, 190, 42, 46, 31, 92, 75, 44, 108, 244, 136, 153},
		[]byte{124, 118, 22, 45, 120, 225, 161, 55, 229, 70, 152, 216, 75, 96, 102, 8, 197, 201, 4, 239, 81, 96, 190, 140, 190, 141, 215, 34, 232, 210, 229, 33},
	)

	// non hardened public key
	fn_test(
		[]byte{2, 79, 159, 213, 46, 118, 186, 102, 200, 181, 232, 99, 231, 120, 211, 74, 147, 164, 202, 97, 251, 52, 106, 156, 154, 44, 135, 101, 129, 92, 68, 115, 203},
		[]byte{73, 181, 191, 18, 41, 90, 225, 158, 90, 94, 40, 160, 159, 76, 153, 218, 103, 211, 41, 14, 70, 99, 249, 37, 197, 39, 115, 105, 159, 191, 84, 242},
		TD_Derive_NonHardenedPub,
		def_u4_test_idx__1,
		[]byte{2, 25, 137, 50, 37, 28, 28, 158, 38, 177, 216, 191, 49, 253, 227, 203, 23, 160, 24, 80, 16, 151, 139, 83, 42, 97, 132, 69, 62, 68, 93, 18, 100},
		[]byte{46, 64, 239, 91, 21, 21, 85, 197, 154, 6, 214, 41, 66, 33, 173, 150, 178, 147, 165, 55, 64, 148, 238, 99, 32, 150, 166, 232, 18, 73, 1, 150},
	)
	fn_test(
		[]byte{2, 79, 159, 213, 46, 118, 186, 102, 200, 181, 232, 99, 231, 120, 211, 74, 147, 164, 202, 97, 251, 52, 106, 156, 154, 44, 135, 101, 129, 92, 68, 115, 203},
		[]byte{73, 181, 191, 18, 41, 90, 225, 158, 90, 94, 40, 160, 159, 76, 153, 218, 103, 211, 41, 14, 70, 99, 249, 37, 197, 39, 115, 105, 159, 191, 84, 242},
		TD_Derive_NonHardenedPub,
		def_u4_test_idx__2,
		[]byte{2, 63, 233, 181, 68, 172, 204, 161, 190, 83, 22, 90, 31, 80, 43, 142, 185, 12, 118, 78, 143, 60, 88, 76, 210, 180, 28, 185, 149, 75, 137, 220, 76},
		[]byte{124, 118, 22, 45, 120, 225, 161, 55, 229, 70, 152, 216, 75, 96, 102, 8, 197, 201, 4, 239, 81, 96, 190, 140, 190, 141, 215, 34, 232, 210, 229, 33},
	)
}

//----------------------------------------------------------------//
// advance test

func Test_MnemonicEncodeDecode(_t *testing.T) {
	fn_test := func(_mnemonicLen int) {
		bt_mnemonic, err := MnemonicNew(_mnemonicLen)
		if err != nil {
			_t.Fatal(err)
		}

		// bt idx -> string
		s_mnemonic, err := MnemonicDecode(bt_mnemonic)
		if err != nil {
			_t.Fatal(err)
		}

		// string -> bt_idx
		bt_mnemonic__new, err := MnemonicEncode(s_mnemonic)
		if err != nil {
			_t.Fatal(err)
		}

		// bt_idx -> string
		s_mnemonic__new, err := MnemonicDecode(bt_mnemonic__new)
		if err != nil {
			_t.Fatal(err)
		}

		// bt idx 비교
		if bytes.Equal(bt_mnemonic, bt_mnemonic__new) != true {
			_t.Fatalf("bt_mnemonic != bt_mnemonic__new | bt_mnemonic : %v | bt_mnemonic__new : %v\n", bt_mnemonic, bt_mnemonic__new)
		}

		// string 비교
		if s_mnemonic != s_mnemonic__new {
			_t.Fatalf("s_mnemonic != s_mnemonic__new | s_mnemonic : %v | s_mnemonic__new : %v\n", s_mnemonic, s_mnemonic__new)
		}
	}

	fn_test(12)
	fn_test(24)
}

func Test_Seed_MasterKey(_t *testing.T) {
	// btcd 라이브러리의 extendedkey 와 같은 지 비교
	fn_test := func(_s_mnemonic, _s_pw__seed, _s_pw__master_key string) {
		// 자체 라이브러리
		bt_mnemonic, err := MnemonicEncode(_s_mnemonic)
		if err != nil {
			_t.Fatal(err)
		}
		bt_seed, err := SeedGet(bt_mnemonic, _s_pw__seed)
		if err != nil {
			_t.Fatal(err)
		}
		bt_child__key_priv, bt_child__chaincode, err := MasterKeyGet(bt_seed, []byte(_s_pw__master_key))
		if err != nil {
			_t.Fatal(err)
		}

		// btcd 라이브러리
		bt_seed__from_lib, err := bip39.NewSeedWithErrorChecking(_s_mnemonic, _s_pw__seed)
		if err != nil {
			_t.Fatal(err)
		}

		pt_extended_key, err := hdkeychain.NewMaster(bt_seed__from_lib, &chaincfg.MainNetParams)
		if err != nil {
			_t.Fatal(err)
		}
		pt_priv_key, err := pt_extended_key.ECPrivKey()
		if err != nil {
			_t.Fatal(err)
		}
		bt_child__key_priv__from_lib := pt_priv_key.Serialize()
		bt_child__chaincode__from_lib := pt_extended_key.ChainCode()

		if bytes.Equal(bt_seed, bt_seed__from_lib) != true {
			_t.Errorf("invalid seed | expect : %v | result : %v\n", bt_seed, bt_seed__from_lib)
		}
		if bytes.Equal(bt_child__key_priv, bt_child__key_priv__from_lib) != true {
			_t.Errorf("invalid child key priv | expect : %v | result : %v\n", bt_child__key_priv, bt_child__key_priv__from_lib)
		}
		if bytes.Equal(bt_child__chaincode, bt_child__chaincode__from_lib) != true {
			_t.Errorf("invalid child chaincode | expect : %v | result : %v\n", bt_child__chaincode, bt_child__chaincode__from_lib)
		}
	}
	DEF_s_seed__for_master_key := "Bitcoin seed"

	// 고정 니모닉 사용
	{
		fn_test(def_s_mnemonic__12, def_s_pw, DEF_s_seed__for_master_key)
		fn_test(def_s_mnemonic__24, def_s_pw, DEF_s_seed__for_master_key)
	}

	// 임의로 생성된 니모닉 사용
	{
		bt_mnemonic__rand, _ := MnemonicNew(12)
		s_mnemonic__rand, _ := MnemonicDecode(bt_mnemonic__rand)
		fn_test(s_mnemonic__rand, def_s_pw, DEF_s_seed__for_master_key)

		bt_mnemonic__rand, _ = MnemonicNew(24)
		s_mnemonic__rand, _ = MnemonicDecode(bt_mnemonic__rand)
		fn_test(s_mnemonic__rand, def_s_pw, DEF_s_seed__for_master_key)
	}
}

// 임시 - derive 테스트 필요
